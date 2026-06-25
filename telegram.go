package main

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

var (
	activeScans   = make(chan struct{}, 3) // Limit concurrent scans to 3
	userScans     = make(map[int64]bool)
	userScansMu   sync.Mutex
	domainPattern = regexp.MustCompile(`^(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`)
)

func isUserScanning(userID int64) bool {
	userScansMu.Lock()
	defer userScansMu.Unlock()
	return userScans[userID]
}

func setUserScanning(userID int64, scanning bool) {
	userScansMu.Lock()
	defer userScansMu.Unlock()
	if scanning {
		userScans[userID] = true
	} else {
		delete(userScans, userID)
	}
}

func cleanDomain(input string) string {
	input = strings.TrimSpace(input)
	input = strings.ToLower(input)
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimSuffix(input, "/")
	input = strings.Split(input, "/")[0]
	input = strings.TrimPrefix(input, "www.")
	return input
}

func StartTelegramBot() {
	cfg := GetConfig()
	bot, err := tgbotapi.NewBotAPI(cfg.TelegramBotToken)
	if err != nil {
		LogEvent("Lỗi khởi tạo Telegram Bot API: %v", err)
		return
	}

	bot.Debug = false
	LogEvent("Telegram Bot [%s] đang chạy...", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		go handleMessage(bot, update.Message)
	}
}

func handleMessage(bot *tgbotapi.BotAPI, msg *tgbotapi.Message) {
	cfg := GetConfig()
	userID := msg.From.ID
	chatID := msg.Chat.ID
	username := msg.From.UserName
	firstName := msg.From.FirstName
	lastName := msg.From.LastName

	// Register or update user stats
	user := globalUsers.RegisterOrUpdateUser(userID, username, firstName, lastName)

	// Check if banned
	if user.IsBanned {
		sendTextMessage(bot, chatID, "🚫 <b>Tài khoản của bạn đã bị Admin chặn quyền sử dụng hệ thống.</b>")
		return
	}

	isAdmin := userID == cfg.TelegramAdminID

	// Check bot status (only Admin can bypass when Bot is off)
	if !cfg.BotEnabled && !isAdmin {
		sendTextMessage(bot, chatID, "⚠️ <b>Hệ thống hiện đang tạm đóng cửa để bảo trì bởi Admin.</b> Vui lòng quay lại sau.")
		return
	}

	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return
	}

	// Route Command
	if strings.HasPrefix(text, "/") {
		parts := strings.Split(text, " ")
		command := parts[0]
		// Strip bot username from command: e.g. "/check@botname" -> "/check"
		if idx := strings.Index(command, "@"); idx != -1 {
			command = command[:idx]
		}
		args := parts[1:]

		switch command {
		case "/start":
			sendStartMessage(bot, chatID, firstName)
		case "/help":
			sendHelpMessage(bot, chatID, isAdmin)
		case "/status":
			sendStatusMessage(bot, chatID)
		case "/check":
			if len(args) == 0 {
				sendTextMessage(bot, chatID, "❌ Vui lòng nhập tên miền cần kiểm tra.\nVí dụ: <code>/check google.com</code>")
				return
			}
			runAsyncScan(bot, chatID, userID, username, args[0], false)
		case "/fullcheck":
			if len(args) == 0 {
				sendTextMessage(bot, chatID, "❌ Vui lòng nhập tên miền cần kiểm tra.\nVí dụ: <code>/fullcheck google.com</code>")
				return
			}
			runAsyncScan(bot, chatID, userID, username, args[0], true)

		// Admin Commands
		case "/admin":
			if !isAdmin {
				if msg.Chat.IsPrivate() {
					sendTextMessage(bot, chatID, "❌ Lệnh này chỉ dành cho Admin.")
				}
				return
			}
			sendAdminMenu(bot, chatID)
		case "/toggle":
			if !isAdmin {
				return
			}
			newStatus := !cfg.BotEnabled
			_ = UpdateBotEnabled(newStatus)
			statusStr := "BẬT"
			if !newStatus {
				statusStr = "TẮT"
			}
			sendTextMessage(bot, chatID, fmt.Sprintf("🤖 Trạng thái hoạt động của Bot đã được Admin chuyển sang: <b>%s</b>", statusStr))
			LogEvent("Admin %d đã đổi trạng thái bot thành: %s", userID, statusStr)
		case "/users":
			if !isAdmin {
				return
			}
			sendUsersList(bot, chatID)
		case "/ban":
			if !isAdmin {
				return
			}
			if len(args) == 0 {
				sendTextMessage(bot, chatID, "❌ Vui lòng nhập ID người dùng cần chặn.\nVí dụ: <code>/ban 12345678</code>")
				return
			}
			targetID, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				sendTextMessage(bot, chatID, "❌ ID người dùng không hợp lệ.")
				return
			}
			if targetID == cfg.TelegramAdminID {
				sendTextMessage(bot, chatID, "❌ Bạn không thể tự chặn chính mình!")
				return
			}
			if globalUsers.SetBanned(targetID, true) {
				sendTextMessage(bot, chatID, fmt.Sprintf("🚫 Đã chặn người dùng có ID: <code>%d</code>", targetID))
				LogEvent("Admin đã chặn người dùng: %d", targetID)
			} else {
				sendTextMessage(bot, chatID, "❌ Không tìm thấy người dùng này trong cơ sở dữ liệu.")
			}
		case "/unban":
			if !isAdmin {
				return
			}
			if len(args) == 0 {
				sendTextMessage(bot, chatID, "❌ Vui lòng nhập ID người dùng cần bỏ chặn.\nVí dụ: <code>/unban 12345678</code>")
				return
			}
			targetID, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				sendTextMessage(bot, chatID, "❌ ID người dùng không hợp lệ.")
				return
			}
			if globalUsers.SetBanned(targetID, false) {
				sendTextMessage(bot, chatID, fmt.Sprintf("✅ Đã mở chặn người dùng có ID: <code>%d</code>", targetID))
				LogEvent("Admin đã mở chặn người dùng: %d", targetID)
			} else {
				sendTextMessage(bot, chatID, "❌ Không tìm thấy người dùng này trong cơ sở dữ liệu.")
			}
		case "/logs":
			if !isAdmin {
				return
			}
			sendLogs(bot, chatID)
		case "/stats":
			if !isAdmin {
				return
			}
			sendStats(bot, chatID)
		default:
			if msg.Chat.IsPrivate() {
				sendTextMessage(bot, chatID, "❓ Lệnh không hợp lệ. Gửi <code>/help</code> để xem hướng dẫn.")
			}
		}
	}
}

func sendTextMessage(bot *tgbotapi.BotAPI, chatID int64, text string) {
	if len(text) <= 4000 {
		msg := tgbotapi.NewMessage(chatID, text)
		msg.ParseMode = tgbotapi.ModeHTML
		_, err := bot.Send(msg)
		if err != nil {
			LogEvent("Lỗi gửi tin nhắn Telegram: %v", err)
		}
		return
	}

	lines := strings.Split(text, "\n")
	var chunk strings.Builder
	insidePre := false

	for _, line := range lines {
		lineLen := len(line) + 1
		extraLen := 0
		if insidePre {
			extraLen = 6 // "</pre>"
		}

		if chunk.Len()+lineLen+extraLen > 4000 {
			if chunk.Len() > 0 {
				sendStr := chunk.String()
				if insidePre {
					sendStr += "</pre>"
				}
				msg := tgbotapi.NewMessage(chatID, sendStr)
				msg.ParseMode = tgbotapi.ModeHTML
				_, err := bot.Send(msg)
				if err != nil {
					LogEvent("Lỗi gửi tin nhắn Telegram (chunk): %v", err)
				}
				chunk.Reset()
				if insidePre {
					chunk.WriteString("<pre>")
				}
			}
		}

		if strings.Contains(line, "<pre>") {
			insidePre = true
		}

		if chunk.Len() > 0 {
			chunk.WriteString("\n")
		}
		chunk.WriteString(line)

		if strings.Contains(line, "</pre>") {
			insidePre = false
		}
	}

	if chunk.Len() > 0 {
		sendStr := chunk.String()
		if insidePre {
			sendStr += "</pre>"
		}
		msg := tgbotapi.NewMessage(chatID, sendStr)
		msg.ParseMode = tgbotapi.ModeHTML
		_, err := bot.Send(msg)
		if err != nil {
			LogEvent("Lỗi gửi tin nhắn Telegram (cuối): %v", err)
		}
	}
}

func sendStartMessage(bot *tgbotapi.BotAPI, chatID int64, firstName string) {
	welcome := fmt.Sprintf("👋 <b>Xin chào %s!</b>\n\n"+
		"Chào mừng bạn đến với <b>Titan God Cloudflare Real IP Finder Bot</b>. "+
		"Tôi giúp bạn tìm kiếm địa chỉ IP gốc thực sự của các trang web đứng sau Cloudflare bằng nhiều phương pháp OSINT và quét mạng chuyên sâu.\n\n"+
		"🔎 <b>Sử dụng cơ bản:</b> Chỉ cần gửi trực tiếp tên miền (ví dụ: <code>google.com</code>) hoặc sử dụng lệnh <code>/check tên_miền</code>.\n\n"+
		"📖 Sử dụng lệnh <code>/help</code> để xem toàn bộ danh sách lệnh.", firstName)
	sendTextMessage(bot, chatID, welcome)
}

func sendHelpMessage(bot *tgbotapi.BotAPI, chatID int64, isAdmin bool) {
	help := "📖 <b>HƯỚNG DẪN SỬ DỤNG BOT:</b>\n\n" +
		"• Gửi trực tiếp tên miền hoặc sử dụng lệnh:\n" +
		"  <code>/check tên_miền</code> - Quét nhanh IP gốc (Khuyên dùng, thời gian chạy ~10-15s).\n" +
		"• <code>/fullcheck tên_miền</code> - Quét đầy đủ nâng cao (Bao gồm brute-force subdomain và quét subnet /24, thời gian quét từ 1-3 phút).\n" +
		"• <code>/status</code> - Xem trạng thái hoạt động của hệ thống bot.\n\n"

	if isAdmin {
		help += "⚙️ <b>LỆNH DÀNH CHO ADMIN:</b>\n" +
			"• <code>/admin</code> - Mở menu quản trị của Admin.\n" +
			"• <code>/toggle</code> - Bật/Tắt Bot đối với người dùng thường.\n" +
			"• <code>/users</code> - Xem danh sách người dùng đã đăng ký.\n" +
			"• <code>/ban &lt;user_id&gt;</code> - Chặn người dùng sử dụng bot.\n" +
			"• <code>/unban &lt;user_id&gt;</code> - Bỏ chặn người dùng.\n" +
			"• <code>/logs</code> - Xem log hoạt động và nhận file log hệ thống.\n" +
			"• <code>/stats</code> - Xem thống kê hoạt động hệ thống."
	}

	sendTextMessage(bot, chatID, help)
}

func sendStatusMessage(bot *tgbotapi.BotAPI, chatID int64) {
	cfg := GetConfig()
	statusStr := "Đang hoạt động 🟢"
	if !cfg.BotEnabled {
		statusStr = "Đang bảo trì 🔴 (Chỉ Admin sử dụng)"
	}

	queueLen := len(activeScans)

	msg := fmt.Sprintf("📊 <b>TRẠNG THÁI HỆ THỐNG:</b>\n\n"+
		"• <b>Trạng thái bot:</b> %s\n"+
		"• <b>Yêu cầu đang quét song song:</b> <code>%d/3</code>\n"+
		"• <b>Chế độ biên dịch:</b> <i>Titan God Production (Go 1.25)</i>", statusStr, queueLen)

	sendTextMessage(bot, chatID, msg)
}

func sendAdminMenu(bot *tgbotapi.BotAPI, chatID int64) {
	cfg := GetConfig()
	statusStr := "BẬT 🟢"
	if !cfg.BotEnabled {
		statusStr = "TẮT 🔴"
	}

	menu := fmt.Sprintf("⚙️ <b>TRANG QUẢN TRỊ ADMIN:</b>\n\n"+
		"• <b>Hoạt động của Bot:</b> <code>%s</code>\n"+
		"• <b>ID Admin của bạn:</b> <code>%d</code>\n\n"+
		"👉 <i>Hãy click các lệnh dưới đây để thao tác nhanh:</i>\n"+
		"- Thay đổi trạng thái hoạt động bot: /toggle\n"+
		"- Xem danh sách người dùng: /users\n"+
		"- Xem thống kê chi tiết: /stats\n"+
		"- Tải tệp nhật ký / xem logs: /logs", statusStr, cfg.TelegramAdminID)

	sendTextMessage(bot, chatID, menu)
}

func sendUsersList(bot *tgbotapi.BotAPI, chatID int64) {
	users := globalUsers.GetAllUsers()
	if len(users) == 0 {
		sendTextMessage(bot, chatID, "👤 Chưa có người dùng nào đăng ký trong hệ thống.")
		return
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].ScanCount > users[j].ScanCount
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("👤 <b>DANH SÁCH NGƯỜI DÙNG (%d):</b>\n\n", len(users)))

	for i, u := range users {
		banStatus := "Hoạt động"
		if u.IsBanned {
			banStatus = "<b>ĐÃ CHẶN 🚫</b>"
		}
		name := u.FirstName
		if u.LastName != "" {
			name += " " + u.LastName
		}
		userLink := fmt.Sprintf("<a href=\"tg://user?id=%d\">%s</a>", u.ID, name)
		if u.Username != "" {
			userLink += fmt.Sprintf(" (@%s)", u.Username)
		}

		sb.WriteString(fmt.Sprintf("%d. %s\n   ├ ID: <code>%d</code>\n   ├ Quét: %d lần\n   └ Trạng thái: %s\n\n", i+1, userLink, u.ID, u.ScanCount, banStatus))

		// Avoid hitting telegram message size limit
		if sb.Len() > 3000 {
			sendTextMessage(bot, chatID, sb.String())
			sb.Reset()
		}
	}

	if sb.Len() > 0 {
		sendTextMessage(bot, chatID, sb.String())
	}
}

func sendStats(bot *tgbotapi.BotAPI, chatID int64) {
	users := globalUsers.GetAllUsers()
	totalScans := 0
	bannedCount := 0
	for _, u := range users {
		totalScans += u.ScanCount
		if u.IsBanned {
			bannedCount++
		}
	}

	stats := fmt.Sprintf("📊 <b>THỐNG KÊ HOẠT ĐỘNG HỆ THỐNG:</b>\n\n"+
		"• <b>Tổng số người dùng:</b> <code>%d</code> người\n"+
		"• <b>Số người dùng bị chặn:</b> <code>%d</code> người\n"+
		"• <b>Tổng số lượt kiểm tra IP gốc:</b> <code>%d</code> lượt\n"+
		"• <b>Đang quét đồng thời:</b> <code>%d</code> tiến trình", len(users), bannedCount, totalScans, len(activeScans))

	sendTextMessage(bot, chatID, stats)
}

func sendLogs(bot *tgbotapi.BotAPI, chatID int64) {
	lines, err := globalLogger.GetLastLogs(20)
	if err != nil {
		sendTextMessage(bot, chatID, fmt.Sprintf("❌ Lỗi đọc logs: %v", err))
		return
	}

	var sb strings.Builder
	sb.WriteString("📋 <b>20 DÒNG LOG GẦN NHẤT:</b>\n\n")
	sb.WriteString("<pre>")
	for _, line := range lines {
		sb.WriteString(htmlEscape(line) + "\n")
	}
	sb.WriteString("</pre>")
	sendTextMessage(bot, chatID, sb.String())

	// Send full scan_logs.txt file
	filePath := "scan_logs.txt"
	if _, err := os.Stat(filePath); err == nil {
		doc := tgbotapi.NewDocument(chatID, tgbotapi.FilePath(filePath))
		doc.Caption = "📁 File scan_logs.txt đầy đủ"
		_, err = bot.Send(doc)
		if err != nil {
			LogEvent("Lỗi gửi file log cho Admin: %v", err)
		}
	}
}

func htmlEscape(in string) string {
	in = strings.ReplaceAll(in, "&", "&amp;")
	in = strings.ReplaceAll(in, "<", "&lt;")
	in = strings.ReplaceAll(in, ">", "&gt;")
	return in
}

func runAsyncScan(bot *tgbotapi.BotAPI, chatID int64, userID int64, username string, rawDomain string, isFullScan bool) {
	if isUserScanning(userID) {
		sendTextMessage(bot, chatID, "❌ <b>Bạn đã có một yêu cầu quét đang chạy.</b> Vui lòng chờ yêu cầu trước hoàn thành.")
		return
	}

	domain := cleanDomain(rawDomain)
	if !domainPattern.MatchString(domain) {
		sendTextMessage(bot, chatID, "❌ <b>Tên miền không hợp lệ hoặc không đúng định dạng.</b>")
		return
	}

	setUserScanning(userID, true)

	go func() {
		defer setUserScanning(userID, false)

		// Queue/Semaphore management
		select {
		case activeScans <- struct{}{}:
			// Got a slot immediately
		default:
			sendTextMessage(bot, chatID, "⏳ <b>Hệ thống đang bận.</b> Yêu cầu quét của bạn đã được thêm vào hàng đợi, sẽ tự động chạy khi có lượt...")
			activeScans <- struct{}{} // Wait/block until slot is available
		}

		defer func() {
			<-activeScans
		}()

		// Start scan notification
		scanType := "Quét Nhanh"
		if isFullScan {
			scanType = "Quét Đầy Đủ"
		}

		LogEvent("Bắt đầu quét [%s] cho domain: %s (Yêu cầu bởi ID: %d)", scanType, domain, userID)

		statusMsgText := fmt.Sprintf("🔍 <b>Đang thực hiện %s cho domain:</b> <code>%s</code>...\n\n"+
			"⏱️ <i>Hệ thống đang khởi tạo các tiến trình kiểm tra gốc...</i>", scanType, domain)
		
		msgConfig := tgbotapi.NewMessage(chatID, statusMsgText)
		msgConfig.ParseMode = tgbotapi.ModeHTML
		statusMsg, err := bot.Send(msgConfig)
		hasStatusMsg := err == nil

		// Create Reaper
		reaper := NewOriginReaper(domain)

		// Capture scan progress logs
		var progressLogs []string
		var logMu sync.Mutex
		reaper.LogFunc = func(format string, args ...interface{}) {
			logMu.Lock()
			defer logMu.Unlock()
			line := fmt.Sprintf(format, args...)
			line = strings.TrimSpace(line)
			if line != "" {
				progressLogs = append(progressLogs, line)
			}
		}

		// Initial CDN latency check
		start := time.Now()
		c := &http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get("https://" + domain)
		if err == nil {
			reaper.CFLatency = time.Since(start)
			resp.Body.Close()
		}

		// Run Phases
		reaper.FetchCloudflareIPs()

		// Update message: Phase 0 OSINT
		if hasStatusMsg {
			statusMsgText = fmt.Sprintf("🔍 <b>Đang thực hiện %s cho domain:</b> <code>%s</code>...\n\n"+
				"🔄 <b>Bước 1/4:</b> Đang thực hiện tìm kiếm rò rỉ OSINT (Shodan, HackerTarget, CT Logs)...", scanType, domain)
			updateMessage(bot, chatID, statusMsg.MessageID, statusMsgText)
		}

		reaper.ShodanOSINT()
		reaper.SearchCrtSh()
		reaper.SearchHackerTarget()

		// If Full Scan, run subdomain & subnet check
		if isFullScan {
			reaper.LoadSubdomains()

			if hasStatusMsg {
				statusMsgText = fmt.Sprintf("🔍 <b>Đang thực hiện %s cho domain:</b> <code>%s</code>...\n\n"+
					"🔄 <b>Bước 2/4:</b> Đang trích xuất và phân tích subdomain diện rộng (24k key)...", scanType, domain)
				updateMessage(bot, chatID, statusMsg.MessageID, statusMsgText)
			}
			reaper.ResolveSubdomains()

			if hasStatusMsg {
				statusMsgText = fmt.Sprintf("🔍 <b>Đang thực hiện %s cho domain:</b> <code>%s</code>...\n\n"+
					"🔄 <b>Bước 3/4:</b> Giám sát các dải mạng Subnet /24 xung quanh IP rò rỉ...", scanType, domain)
				updateMessage(bot, chatID, statusMsg.MessageID, statusMsgText)
			}
			reaper.SubnetScan()
		}

		// Phase: Verification
		if hasStatusMsg {
			statusMsgText = fmt.Sprintf("🔍 <b>Đang thực hiện %s cho domain:</b> <code>%s</code>...\n\n"+
				"🔄 <b>Bước 4/4:</b> Đang chạy kiểm tra SSL Handshake & HTTP Host Header xác minh IP gốc...", scanType, domain)
			updateMessage(bot, chatID, statusMsg.MessageID, statusMsgText)
		}

		// SSL Handshake check
		reaper.VerifyAllUTLS()

		// HTTP Host Header confirmation
		reaper.HostHeaderVerify()

		// Build Report HTML
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("🔍 <b>BÁO CÁO KẾT QUẢ TÌM IP GỐC</b>\n\n"+
			"• <b>Tên miền:</b> <code>%s</code>\n"+
			"• <b>Hình thức:</b> <code>%s</code>\n"+
			"• <b>Thời gian quét:</b> <code>%s</code>\n",
			domain, scanType, time.Now().Format("02-01-2006 15:04:05")))

		if reaper.CFLatency > 0 {
			sb.WriteString(fmt.Sprintf("• <b>Độ trễ Cloudflare:</b> <code>%s</code>\n", reaper.CFLatency))
		}
		sb.WriteString("\n==================================\n")
		sb.WriteString("<b>IP GỐC PHÁT HIỆN ĐƯỢC:</b>\n\n")

		foundIPs := 0
		var confirmedList []string
		var verifiedList []string
		var potentialList []string

		reaper.mu.Lock()
		for ip, c := range reaper.Results {
			foundIPs++
			detail := translateVector(c.Vector)
			if c.Details != "" {
				detail = c.Details
			}

			if c.Confirmed {
				confirmedList = append(confirmedList, fmt.Sprintf("🔥 <b>[XÁC NHẬN GỐC]</b> <code>%s</code>\n└ <i>Chi tiết: %s</i>", ip, detail))
			} else if c.Verified {
				verifiedList = append(verifiedList, fmt.Sprintf("✅ <b>[XÁC THỰC SNI]</b> <code>%s</code>\n└ <i>Chi tiết: %s</i>", ip, detail))
			} else {
				potentialList = append(potentialList, fmt.Sprintf("❓ <b>[NGHI VẤN]</b> <code>%s</code>\n└ <i>Chi tiết: %s</i>", ip, detail))
			}
		}
		reaper.mu.Unlock()

		if foundIPs == 0 {
			sb.WriteString("❌ <i>Không tìm thấy IP gốc trực tiếp nào của tên miền này bên ngoài Cloudflare.</i>\n")
		} else {
			for _, item := range confirmedList {
				sb.WriteString(item + "\n\n")
			}
			for _, item := range verifiedList {
				sb.WriteString(item + "\n\n")
			}
			for _, item := range potentialList {
				sb.WriteString(item + "\n\n")
			}
		}
		sb.WriteString("==================================\n")
		sb.WriteString("<i>Cảm ơn bạn đã sử dụng dịch vụ của Titan God!</i>")

		// Delete status message and send final report
		if hasStatusMsg {
			deleteMessage(bot, chatID, statusMsg.MessageID)
		}
		sendTextMessage(bot, chatID, sb.String())

		// Update user stats
		globalUsers.RecordScan(userID)

		// Log results to file
		var ipReportStr []string
		reaper.mu.Lock()
		for ip, c := range reaper.Results {
			status := "POTENTIAL"
			if c.Confirmed {
				status = "CONFIRMED"
			} else if c.Verified {
				status = "VERIFIED"
			}
			ipReportStr = append(ipReportStr, fmt.Sprintf("%s(%s)", ip, status))
		}
		reaper.mu.Unlock()

		LogEvent("Quét hoàn tất cho %s. Phát hiện: [%s]. Người yêu cầu: ID %d (%s)", domain, strings.Join(ipReportStr, ", "), userID, username)
	}()
}

func updateMessage(bot *tgbotapi.BotAPI, chatID int64, messageID int, text string) {
	msg := tgbotapi.NewEditMessageText(chatID, messageID, text)
	msg.ParseMode = tgbotapi.ModeHTML
	_, _ = bot.Send(msg)
}

func deleteMessage(bot *tgbotapi.BotAPI, chatID int64, messageID int) {
	msg := tgbotapi.NewDeleteMessage(chatID, messageID)
	_, _ = bot.Send(msg)
}
