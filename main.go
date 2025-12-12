package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
	"github.com/gorilla/websocket"
)

var (
	UUID        = getEnv("UUID", "5efabea4-f6d4-91fd-b8f0-17e004c89c60")
	NEZHA_SERVER = getEnv("NEZHA_SERVER", "")
	NEZHA_PORT   = getEnv("NEZHA_PORT", "")
	NEZHA_KEY    = getEnv("NEZHA_KEY", "")
	DOMAIN       = getEnv("DOMAIN", "1234.abc.com")
	AUTO_ACCESS  = getEnv("AUTO_ACCESS", "false") == "true"
	WSPATH       = getEnv("WSPATH", UUID[:8])
	SUB_PATH     = getEnv("SUB_PATH", "sub")
	NAME         = getEnv("NAME", "")
	PORT         = getEnv("PORT", "3000")

	// 内存池，优化 GC
	bufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 64*1024) // 64KB buffer
		},
	}
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	uuidBytes []byte
	currentISP = "Unknown"
)

func init() {
	cleanUUID := strings.ReplaceAll(UUID, "-", "")
	var err error
	uuidBytes, err = hex.DecodeString(cleanUUID)
	if err != nil {
		log.Fatalf("Invalid UUID: %v", err)
	}
}

func main() {
	go getISP()
	go runNezha()

	// 启动保活任务
	if AUTO_ACCESS {
		go addAccessTask()
	}

	// 路由设置
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/"+SUB_PATH, handleSub)
	http.HandleFunc("/"+WSPATH, handleWebSocket)

	log.Printf("Server is running on port %s", PORT)
	if err := http.ListenAndServe(":"+PORT, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	content, err := os.ReadFile("index.html")
	if err == nil {
		w.Write(content)
	} else {
		w.Write([]byte("Hello world!"))
	}
}

func handleSub(w http.ResponseWriter, r *http.Request) {
	namePart := currentISP
	if NAME != "" {
		namePart = NAME + "-" + currentISP
	}
	
	vlessURL := fmt.Sprintf("vless://%s@cdns.doon.eu.org:443?encryption=none&security=tls&sni=%s&fp=chrome&type=ws&host=%s&path=%%2F%s#%s",
		UUID, DOMAIN, DOMAIN, WSPATH, namePart)
	trojanURL := fmt.Sprintf("trojan://%s@cdns.doon.eu.org:443?security=tls&sni=%s&fp=chrome&type=ws&host=%s&path=%%2F%s#%s",
		UUID, DOMAIN, DOMAIN, WSPATH, namePart)
	
	subscription := vlessURL + "\n" + trojanURL
	base64Content := base64.StdEncoding.EncodeToString([]byte(subscription))
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(base64Content + "\n"))
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer wsConn.Close()
	messageType, firstMsg, err := wsConn.ReadMessage()
	if err != nil {
		return
	}

	// 封装 WebSocket 为 io.ReadWriteCloser 以便通用处理
	stream := &wsStream{conn: wsConn, msgType: messageType, readBuf: bytes.NewReader(firstMsg)}

	// 协议探测
	// VLESS: [Version(1)] [UUID(16)] [Addons(1)] ...
	// Trojan: [Hex(SHA224(Password))(56)] [CRLF(2)] [Cmd(1)] ...
	
	if len(firstMsg) > 17 && firstMsg[0] == 0 {
		// 尝试 VLESS
		reqID := firstMsg[1:17]
		if bytes.Equal(reqID, uuidBytes) {
			handleVless(stream, firstMsg)
			return
		}
	}

	// 尝试 Trojan
	// Trojan 的前 56 字节是密码的 SHA224 hex 字符串
	if len(firstMsg) >= 56 {
		// 验证密码
		targetHash := sha256.Sum224([]byte(UUID))
		targetHex := hex.EncodeToString(targetHash[:])
		
		if string(firstMsg[:56]) == targetHex {
			handleTrojan(stream, firstMsg)
			return
		}
	}
}

// VLESS 协议处理
func handleVless(stream io.ReadWriteCloser, firstMsg []byte) {
	// 解析头部
	// firstMsg 结构: 1-byte ver, 16-byte uuid, 1-byte addons len
	addonLen := int(firstMsg[17])
	// 跳过头部: 1 + 16 + 1 + addonLen
	offset := 19 + addonLen
	if len(firstMsg) < offset+2 {
		return 
	}

	// 读取端口 (BigEndian)
	port := binary.BigEndian.Uint16(firstMsg[offset : offset+2])
	offset += 2

	// 读取地址类型
	atyp := firstMsg[offset]
	offset++

	var host string
	switch atyp {
	case 1: // IPv4
		if len(firstMsg) < offset+4 { return }
		host = net.IP(firstMsg[offset : offset+4]).String()
		offset += 4
	case 2: // Domain
		if len(firstMsg) < offset+1 { return }
		domainLen := int(firstMsg[offset])
		offset++
		if len(firstMsg) < offset+domainLen { return }
		host = string(firstMsg[offset : offset+domainLen])
		offset += domainLen
	case 3: // IPv6
		if len(firstMsg) < offset+16 { return }
		host = net.IP(firstMsg[offset : offset+16]).String()
		offset += 16
	}

	// 发送 VLESS 响应头部 [Version, AddonsLen]
	stream.Write([]byte{firstMsg[0], 0})
	// 建立连接并转发
	doProxy(stream, host, fmt.Sprintf("%d", port), firstMsg[offset:])
}

// Trojan 协议处理
func handleTrojan(stream io.ReadWriteCloser, firstMsg []byte) {
	offset := 56
	if offset+2 <= len(firstMsg) && firstMsg[offset] == 0x0d && firstMsg[offset+1] == 0x0a {
		offset += 2
	}

	if offset >= len(firstMsg) { return }
	cmd := firstMsg[offset]
	if cmd != 0x01 { return } // 只支持 CONNECT
	offset++

	atyp := firstMsg[offset]
	offset++

	var host string
	switch atyp {
	case 1: // IPv4
		host = net.IP(firstMsg[offset : offset+4]).String()
		offset += 4
	case 3: // Domain
		hostLen := int(firstMsg[offset])
		offset++
		host = string(firstMsg[offset : offset+hostLen])
		offset += hostLen
	case 4: // IPv6
		host = net.IP(firstMsg[offset : offset+16]).String()
		offset += 16
	}

	port := binary.BigEndian.Uint16(firstMsg[offset : offset+2])
	offset += 2

	if offset+2 <= len(firstMsg) && firstMsg[offset] == 0x0d && firstMsg[offset+1] == 0x0a {
		offset += 2
	}
	// Trojan 建立连接后直接转发，不需要回写头部
	doProxy(stream, host, fmt.Sprintf("%d", port), firstMsg[offset:])
}

// 通用数据转发逻辑
func doProxy(clientConn io.ReadWriteCloser, host, port string, initialPayload []byte) {
	defer clientConn.Close()
	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// 如果有剩余的 payload，先写入目标
	if len(initialPayload) > 0 {
		targetConn.Write(initialPayload)
	}

	// 双向拷贝
	errChan := make(chan error, 2)
	go func() {
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		_, err := io.CopyBuffer(targetConn, clientConn, buf)
		errChan <- err
		fmt.Println("upstream ...")
	}()

	go func() {
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		_, err := io.CopyBuffer(clientConn, targetConn, buf)
		errChan <- err
		fmt.Println("downstream ...")
	}()
	err1 := <-errChan 
	if err1 != nil {
		fmt.Println("upstream error", err1)
	}
	err2 := <-errChan 
	if err2 != nil {
		fmt.Println("downstream error", err2)
	}
}

// WebSocket 适配器：将 WS 封装为 io.ReadWriteCloser
type wsStream struct {
	conn    *websocket.Conn
	msgType int
	readBuf io.Reader
	mu      sync.Mutex
}

func (s *wsStream) Read(p []byte) (int, error) {
	if s.readBuf != nil {
		n, err := s.readBuf.Read(p)
		if err == io.EOF {
			s.readBuf = nil
			return n, nil // 继续读取下一条消息
		}
		return n, err
	}
	
	_, msg, err := s.conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	s.readBuf = bytes.NewReader(msg)
	return s.Read(p)
}

func (s *wsStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// BinaryMessage 对应 2
	err := s.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *wsStream) Close() error {
	return s.conn.Close()
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getISP() {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://speed.cloudflare.com/meta")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	var data struct {
		Country        string `json:"country"`
		AsOrganization string `json:"asOrganization"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
		currentISP = strings.ReplaceAll(fmt.Sprintf("%s-%s", data.Country, data.AsOrganization), " ", "_")
	}
}

func runNezha() {
	if NEZHA_SERVER == "" && NEZHA_KEY == "" {
		log.Println("NEZHA variable is empty, skip running")
		return
	}

	// 检查是否已经在运行
	checkCmd := exec.Command("sh", "-c", "ps aux | grep -v grep | grep './npm'")
	if out, _ := checkCmd.Output(); len(out) > 0 {
		log.Println("npm is already running, skip...")
		return
	}

	// 下载 Agent
	agentUrl := getDownloadUrl()
	if err := downloadFile(agentUrl, "npm"); err != nil {
		log.Printf("Download nezha agent failed: %v", err)
		return
	}
	
	if err := os.Chmod("npm", 0755); err != nil {
		log.Printf("Chmod failed: %v", err)
		return
	}

	// 构建命令
	var cmd *exec.Cmd
	tlsPorts := []string{"443", "8443", "2096", "2087", "2083", "2053"}
	
	if NEZHA_SERVER != "" && NEZHA_PORT != "" && NEZHA_KEY != "" {
		useTls := ""
		for _, p := range tlsPorts {
			if NEZHA_PORT == p { useTls = "--tls"; break }
		}
		// Go 中直接运行命令，不需要 setsid nohup，因为我们是在 goroutine 中运行
		args := []string{"-s", fmt.Sprintf("%s:%s", NEZHA_SERVER, NEZHA_PORT), "-p", NEZHA_KEY, "--disable-auto-update", "--report-delay", "4", "--skip-conn", "--skip-procs"}
		if useTls != "" {
			args = append(args, useTls)
		}
		cmd = exec.Command("./npm", args...)
	} else if NEZHA_SERVER != "" && NEZHA_KEY != "" {
		// V0 Agent Config 逻辑
		port := "80"
		if strings.Contains(NEZHA_SERVER, ":") {
			parts := strings.Split(NEZHA_SERVER, ":")
			port = parts[len(parts)-1]
		}
		isTls := "false"
		for _, p := range tlsPorts {
			if port == p { isTls = "true"; break }
		}
		
		configContent := fmt.Sprintf(`client_secret: %s
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: %s
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: %s
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: %s`, NEZHA_KEY, NEZHA_SERVER, isTls, UUID)
		
		os.WriteFile("config.yaml", []byte(configContent), 0644)
		cmd = exec.Command("./npm", "-c", "config.yaml")
	}

	if cmd != nil {
		if err := cmd.Start(); err != nil {
			log.Printf("Nezha start error: %v", err)
		} else {
			log.Println("npm is running")
			// 3分钟后删除文件
			time.AfterFunc(3*time.Minute, func() {
				os.Remove("npm")
				os.Remove("config.yaml")
			})
		}
	}
}

func getDownloadUrl() string {
	arch := runtime.GOARCH
	baseUrl := "https://%s.ssss.nyc.mn"
	domain := ""
	path := "/v1" // 默认 v0 agent
	if NEZHA_PORT != "" {
		path = "/agent" // v1 agent
	}
	
	switch arch {
	case "arm", "arm64":
		domain = "arm64"
	default:
		domain = "amd64"
	}
	
	return fmt.Sprintf(baseUrl, domain) + path
}

func downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func addAccessTask() {
	if DOMAIN == "" { return }
	fullURL := fmt.Sprintf("https://%s/%s", DOMAIN, SUB_PATH)
	payload := map[string]string{"url": fullURL}
	jsonBody, _ := json.Marshal(payload)
	http.Post("https://oooo.serv00.net/add-url", "application/json", bytes.NewBuffer(jsonBody))
	log.Println("Automatic Access Task added")
}