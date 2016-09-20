package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/fasthttp-contrib/sessions"
	_ "github.com/go-sql-driver/mysql"
	"github.com/valyala/fasthttp"
)

var db *sql.DB
var (
	UserLockThreshold int
	IPBanThreshold    int
)

func init() {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?parseTime=true&loc=Local",
		getEnv("ISU4_DB_USER", "root"),
		getEnv("ISU4_DB_PASSWORD", ""),
		getEnv("ISU4_DB_HOST", "localhost"),
		getEnv("ISU4_DB_PORT", "3306"),
		getEnv("ISU4_DB_NAME", "isu4_qualifier"),
	)

	var err error

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}

	UserLockThreshold, err = strconv.Atoi(getEnv("ISU4_USER_LOCK_THRESHOLD", "3"))
	if err != nil {
		panic(err)
	}

	IPBanThreshold, err = strconv.Atoi(getEnv("ISU4_IP_BAN_THRESHOLD", "10"))
	if err != nil {
		panic(err)
	}
}

func Startup() {
	UserRepoSyncFromDB()
	LoginRepoSyncFromDB()
}

func getInit(ctx *fasthttp.RequestCtx) {
	Startup()
	ctx.SetStatusCode(fasthttp.StatusOK)
	fmt.Fprintf(ctx, "ok\n")
}

func getReport(ctx *fasthttp.RequestCtx) {
	bytes, err := json.Marshal(struct {
		BannedIPs   []string `json:"banned_ips"`
		LockedUsers []string `json:"locked_users"`
	}{bannedIPs(), lockedUsers()})
	if err != nil {
		log.Println(err)
		return
	}
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Write(bytes)
}

func getMyPage(ctx *fasthttp.RequestCtx) {
	session := sessions.StartFasthttp(ctx)
	currentUser := getCurrentUser(session.Get("user_id"))
	if currentUser == nil {
		session.Set("notice", "You must be logged in")
		ctx.Redirect("/", 302)
		return
	}
	ll := getLastLogin(currentUser, ctx)

	ctx.SetContentType("text/html")
	ctx.SetStatusCode(fasthttp.StatusOK)
	iw := IsuWriter{ctx}
	iw.WriteString("<!DOCTYPE html>\n<html>\n <head>\n <meta charset=\"UTF-8\">\n <link rel=\"stylesheet\" href=\"/stylesheets/bootstrap.min.css\">\n <link rel=\"stylesheet\" href=\"/stylesheets/bootflat.min.css\">\n <link rel=\"stylesheet\" href=\"/stylesheets/isucon-bank.css\">\n <title>isucon4</title>\n </head>\n <body>\n <div class=\"container\">\n <h1 id=\"topbar\">\n <a href=\"/\"><img src=\"/images/isucon-bank.png\" alt=\"いすこん銀行 オンラインバンキングサービス\"></a>\n </h1>\n ")
	iw.WriteString("<div class=\"alert alert-success\" role=\"alert\">\n ログインに成功しました。<br>\n 未読のお知らせが０件、残っています。\n</div>\n\n<dl class=\"dl-horizontal\">\n <dt>前回ログイン</dt>\n <dd id=\"last-logined-at\">")
	iw.WriteString(ll.CreatedAt.Format("2006-01-02 15:04:05"))
	iw.WriteString("</dd>\n <dt>最終ログインIPアドレス</dt>\n <dd id=\"last-logined-ip\">")
	iw.WriteString(ll.IP)
	iw.WriteString("</dd>\n</dl>\n\n<div class=\"panel panel-default\">\n <div class=\"panel-heading\">\n お客様ご契約ID：")
	iw.WriteString(ll.Login)
	iw.WriteString(" 様の代表口座\n </div>\n <div class=\"panel-body\">\n <div class=\"row\">\n <div class=\"col-sm-4\">\n 普通預金<br>\n <small>東京支店　1111111111</small><br>\n </div>\n <div class=\"col-sm-4\">\n <p id=\"zandaka\" class=\"text-right\">\n ―――円\n </p>\n </div>\n\n <div class=\"col-sm-4\">\n <p>\n <a class=\"btn btn-success btn-block\">入出金明細を表示</a>\n <a class=\"btn btn-default btn-block\">振込・振替はこちらから</a>\n </p>\n </div>\n\n <div class=\"col-sm-12\">\n <a class=\"btn btn-link btn-block\">定期預金・住宅ローンのお申込みはこちら</a>\n </div>\n </div>\n </div>\n</div>")
	iw.WriteString("\n </div>\n\n </body>\n</html>")
}

func postLogin(ctx *fasthttp.RequestCtx) {
	session := sessions.StartFasthttp(ctx)
	user, err := attemptLogin(ctx)

	notice := ""
	if err != nil || user == nil {
		switch err {
		case ErrBannedIP:
			notice = "You're banned."
		case ErrLockedUser:
			notice = "This account is locked."
		default:
			notice = "Wrong username or password"
		}

		session.Set("notice", notice)
		ctx.Redirect("/", 302)
		return
	}

	session.Set("user_id", strconv.Itoa(user.ID))
	ctx.Redirect("/mypage", 302)
}

func getIndex(ctx *fasthttp.RequestCtx) {
	session := sessions.StartFasthttp(ctx)
	flash := getFlash(session, "notice")
	ctx.SetContentType("text/html")

	iw := IsuWriter{ctx}
	iw.WriteString("<!DOCTYPE html>\n<html>\n <head>\n <meta charset=\"UTF-8\">\n <link rel=\"stylesheet\" href=\"/stylesheets/bootstrap.min.css\">\n <link rel=\"stylesheet\" href=\"/stylesheets/bootflat.min.css\">\n <link rel=\"stylesheet\" href=\"/stylesheets/isucon-bank.css\">\n <title>isucon4</title>\n </head>\n <body>\n <div class=\"container\">\n <h1 id=\"topbar\">\n <a href=\"/\"><img src=\"/images/isucon-bank.png\" alt=\"いすこん銀行 オンラインバンキングサービス\"></a>\n </h1>\n ")
	iw.WriteString("<div id=\"be-careful-phising\" class=\"panel panel-danger\">\n <div class=\"panel-heading\">\n <span class=\"hikaru-mozi\">偽画面にご注意ください！</span>\n </div>\n <div class=\"panel-body\">\n <p>偽のログイン画面を表示しお客様の情報を盗み取ろうとする犯罪が多発しています。</p>\n <p>ログイン直後にダウンロード中や、見知らぬウィンドウが開いた場合、<br>すでにウィルスに感染している場合がございます。即座に取引を中止してください。</p>\n <p>また、残高照会のみなど、必要のない場面で乱数表の入力を求められても、<br>絶対に入力しないでください。</p>\n </div>\n</div>\n\n<div class=\"page-header\">\n <h1>ログイン</h1>\n</div>\n\n")
	if 0 < len(flash) {
		iw.WriteString("\n <div id=\"notice-message\" class=\"alert alert-danger\" role=\"alert\">")
		iw.WriteString(flash)
		iw.WriteString("</div>\n")
	}
	iw.WriteString("\n\n<div class=\"container\">\n <form class=\"form-horizontal\" role=\"form\" action=\"/login\" method=\"POST\">\n <div class=\"form-group\">\n <label for=\"input-username\" class=\"col-sm-3 control-label\">お客様ご契約ID</label>\n <div class=\"col-sm-9\">\n <input id=\"input-username\" type=\"text\" class=\"form-control\" placeholder=\"半角英数字\" name=\"login\">\n </div>\n </div>\n <div class=\"form-group\">\n <label for=\"input-password\" class=\"col-sm-3 control-label\">パスワード</label>\n <div class=\"col-sm-9\">\n <input type=\"password\" class=\"form-control\" id=\"input-password\" name=\"password\" placeholder=\"半角英数字・記号（２文字以上）\">\n </div>\n </div>\n <div class=\"form-group\">\n <div class=\"col-sm-offset-3 col-sm-9\">\n <button type=\"submit\" class=\"btn btn-primary btn-lg btn-block\">ログイン</button>\n </div>\n </div>\n </form>\n</div>")
	iw.WriteString("\n </div>\n\n </body>\n</html>")
}

func waitDB() {
	for {
		err := db.Ping()
		if err == nil {
			break
		}
		log.Println(err)
		time.Sleep(time.Second)
	}
}

func main() {
	go func() {
		log.Println(http.ListenAndServe(":6060", nil))
	}()
	startTime := time.Now()

	waitDB()
	Startup()

	m := func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/":
			getIndex(ctx)
		case "/init":
			getInit(ctx)
		case "/report":
			getReport(ctx)
		case "/mypage":
			getMyPage(ctx)
		case "/login":
			postLogin(ctx)
		case "/stylesheets/bootstrap.min.css":
			if ctx.IfModifiedSince(startTime) {
				ctx.Response.Header.SetLastModified(startTime)
				fasthttp.ServeFile(ctx, "../public/stylesheets/bootstrap.min.css")
			} else {
				ctx.NotModified()
			}
		case "/stylesheets/bootflat.min.css":
			if ctx.IfModifiedSince(startTime) {
				ctx.Response.Header.SetLastModified(startTime)
				fasthttp.ServeFile(ctx, "../public/stylesheets/bootflat.min.css")
			} else {
				ctx.NotModified()
			}
		case "/stylesheets/isucon-bank.css":
			if ctx.IfModifiedSince(startTime) {
				ctx.Response.Header.SetLastModified(startTime)
				fasthttp.ServeFile(ctx, "../public/stylesheets/isucon-bank.css")
			} else {
				ctx.NotModified()
			}
		case "/images/isucon-bank.png":
			if ctx.IfModifiedSince(startTime) {
				ctx.Response.Header.SetLastModified(startTime)
				fasthttp.ServeFile(ctx, "../public/images/isucon-bank.png")
			} else {
				ctx.NotModified()
			}
		default:
			ctx.Error("not found", fasthttp.StatusNotFound)
		}
	}
	fasthttp.ListenAndServe(":8080", m)

}
