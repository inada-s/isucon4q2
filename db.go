package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

var (
	ErrBannedIP      = errors.New("Banned IP")
	ErrLockedUser    = errors.New("Locked user")
	ErrUserNotFound  = errors.New("Not found user")
	ErrWrongPassword = errors.New("Wrong password")
)

var (
	UserRepoMtx sync.Mutex
	UserRepo    map[int]User
	UserName2ID map[string]int

	LastLoginRepoMtx sync.Mutex
	LastLoginRepo    map[int]LastLogin
	PrevLoginRepo    map[int]LastLogin

	LoginLogRepoMtx      sync.Mutex
	LoginLogRepo         []LastLogin
	LoginFailedUserCount map[int]int
	LoginFailedIPCount   map[string]int
)

func UserRepoSyncFromDB() {
	UserRepoMtx.Lock()
	UserRepoMtx.Unlock()

	UserRepo = map[int]User{}
	UserName2ID = map[string]int{}

	rows, err := db.Query("SELECT id, login, password_hash, salt FROM users")
	if err != nil {
		log.Println(err)
	}
	for rows.Next() {
		u := User{}
		err = rows.Scan(&u.ID, &u.Login, &u.PasswordHash, &u.Salt)
		if err != nil {
			log.Println(err)
		}
		UserRepo[u.ID] = u
		UserName2ID[u.Login] = u.ID
	}
	rows.Close()
}

func UpdateOnLoginSuccess(ll LastLogin) {
	LoginLogRepoMtx.Lock()
	LastLoginRepoMtx.Lock()
	defer LoginLogRepoMtx.Unlock()
	defer LastLoginRepoMtx.Unlock()

	PrevLoginRepo[ll.UserID] = LastLoginRepo[ll.UserID]
	LastLoginRepo[ll.UserID] = ll
	LoginFailedUserCount[ll.UserID] = 0
	LoginFailedIPCount[ll.IP] = 0
}

func UpdateOnLoginFailed(ll LastLogin) {
	LoginLogRepoMtx.Lock()
	defer LoginLogRepoMtx.Unlock()

	if n, ok := LoginFailedUserCount[ll.UserID]; ok {
		LoginFailedUserCount[ll.UserID] = n + 1
	} else {
		LoginFailedUserCount[ll.UserID] = 1
	}

	if n, ok := LoginFailedIPCount[ll.IP]; ok {
		LoginFailedIPCount[ll.IP] = n + 1
	} else {
		LoginFailedIPCount[ll.IP] = 1
	}
}

func LoginRepoSyncFromDB() {
	rows, err := db.Query("SELECT user_id, login, ip, succeeded, created_at FROM login_log")
	if err != nil {
		log.Println(err)
	}
	LoginLogRepo = make([]LastLogin, 0, 100000)

	LoginLogRepoMtx.Lock()
	LastLoginRepoMtx.Lock()
	LoginFailedUserCount = map[int]int{}
	LoginFailedIPCount = map[string]int{}
	LastLoginRepo = map[int]LastLogin{}
	PrevLoginRepo = map[int]LastLogin{}
	LoginLogRepoMtx.Unlock()
	LastLoginRepoMtx.Unlock()

	for rows.Next() {
		ll := LastLogin{}
		err = rows.Scan(&ll.UserID, &ll.Login, &ll.IP, &ll.Succeeded, &ll.CreatedAt)
		if err != nil {
			log.Println(err)
		}

		LoginLogRepo = append(LoginLogRepo, ll)
		if 0 < ll.Succeeded {
			UpdateOnLoginSuccess(ll)
		} else {
			UpdateOnLoginFailed(ll)
		}
	}
	rows.Close()
}

func GetUserByID(id int) (User, bool) {
	UserRepoMtx.Lock()
	UserRepoMtx.Unlock()

	u, ok := UserRepo[id]
	return u, ok
}

func GetUserByLogin(login string) (User, bool) {
	UserRepoMtx.Lock()
	UserRepoMtx.Unlock()

	id, ok := UserName2ID[login]
	if !ok {
		return User{}, ok
	}
	u, ok := UserRepo[id]
	return u, ok
}

func GetLastLogin(id int) (LastLogin, bool) {
	LastLoginRepoMtx.Lock()
	LastLoginRepoMtx.Unlock()
	ll, ok := LastLoginRepo[id]
	return ll, ok
}

func GetPrevLogin(id int) (LastLogin, bool) {
	LastLoginRepoMtx.Lock()
	LastLoginRepoMtx.Unlock()
	ll, ok := PrevLoginRepo[id]
	return ll, ok
}

func GetLoginFailedUserCount(id int) int {
	LoginLogRepoMtx.Lock()
	LoginLogRepoMtx.Unlock()
	n, ok := LoginFailedUserCount[id]
	if !ok {
		return 0
	}
	return n
}

func GetLoginFailedIPCount(ip string) int {
	LoginLogRepoMtx.Lock()
	LoginLogRepoMtx.Unlock()
	n, ok := LoginFailedIPCount[ip]
	if !ok {
		return 0
	}
	return n
}

func createLoginLog(succeeded bool, remoteAddr, login string, user *User) error {
	succ := 0
	if succeeded {
		succ = 1
	}

	var userId sql.NullInt64
	if user != nil {
		userId.Int64 = int64(user.ID)
		userId.Valid = true
	}

	_, err := db.Exec(
		"INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) "+
			"VALUES (?,?,?,?,?)", time.Now(), userId, login, remoteAddr, succ)

	ll := LastLogin{
		UserID:    user.ID,
		Login:     user.Login,
		IP:        remoteAddr,
		Succeeded: succ,
		CreatedAt: time.Now(),
	}

	if succeeded {
		UpdateOnLoginSuccess(ll)
	} else {
		UpdateOnLoginFailed(ll)
	}

	return err
}

func isLockedUser(user *User) (bool, error) {
	if user == nil {
		return false, nil
	}
	return UserLockThreshold <= GetLoginFailedUserCount(user.ID), nil
}

func isBannedIP(ip string) (bool, error) {
	return IPBanThreshold <= GetLoginFailedIPCount(ip), nil
}

func attemptLogin(ctx *fasthttp.RequestCtx) (*User, error) {
	succeeded := false
	user := &User{}

	loginName := string(ctx.FormValue("login"))
	password := string(ctx.FormValue("password"))

	remoteAddr := ctx.RemoteAddr().String()
	if xForwardedFor := ctx.Request.Header.Peek("X-Forwarded-For"); len(xForwardedFor) > 0 {
		remoteAddr = string(xForwardedFor)
	}

	defer func() {
		createLoginLog(succeeded, remoteAddr, loginName, user)
	}()

	if u, ok := GetUserByLogin(loginName); ok {
		user = &u
	} else {
		user = nil
	}

	if banned, _ := isBannedIP(remoteAddr); banned {
		return nil, ErrBannedIP
	}

	if locked, _ := isLockedUser(user); locked {
		return nil, ErrLockedUser
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	if user.PasswordHash != calcPassHash(password, user.Salt) {
		return nil, ErrWrongPassword
	}

	succeeded = true
	return user, nil
}

func getLastLogin(u *User, ctx *fasthttp.RequestCtx) *LastLogin {
	ll, ok := GetPrevLogin(u.ID)
	if ok {
		return &ll
	}
	ll, _ = GetLastLogin(u.ID)
	return &ll
}

func getCurrentUser(userId interface{}) *User {
	id, err := strconv.Atoi(fmt.Sprint(userId))
	if err != nil {
		return nil
	}
	u, ok := GetUserByID(id)
	if !ok {
		return nil
	}
	return &u
}

func bannedIPs() []string {
	ips := []string{}

	rows, err := db.Query(
		"SELECT ip FROM "+
			"(SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) "+
			"AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?",
		IPBanThreshold,
	)

	if err != nil {
		return ips
	}

	defer rows.Close()
	for rows.Next() {
		var ip string

		if err := rows.Scan(&ip); err != nil {
			return ips
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		return ips
	}

	rowsB, err := db.Query(
		"SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip",
	)

	if err != nil {
		return ips
	}

	defer rowsB.Close()
	for rowsB.Next() {
		var ip string
		var lastLoginId int

		if err := rows.Scan(&ip, &lastLoginId); err != nil {
			return ips
		}

		var count int

		err = db.QueryRow(
			"SELECT COUNT(1) AS cnt FROM login_log WHERE ip = ? AND ? < id",
			ip, lastLoginId,
		).Scan(&count)

		if err != nil {
			return ips
		}

		if IPBanThreshold <= count {
			ips = append(ips, ip)
		}
	}
	if err := rowsB.Err(); err != nil {
		return ips
	}

	return ips
}

func lockedUsers() []string {
	userIds := []string{}

	rows, err := db.Query(
		"SELECT user_id, login FROM "+
			"(SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY user_id) "+
			"AS t0 WHERE t0.user_id IS NOT NULL AND t0.max_succeeded = 0 AND t0.cnt >= ?",
		UserLockThreshold,
	)

	if err != nil {
		return userIds
	}

	defer rows.Close()
	for rows.Next() {
		var userId int
		var login string

		if err := rows.Scan(&userId, &login); err != nil {
			return userIds
		}
		userIds = append(userIds, login)
	}
	if err := rows.Err(); err != nil {
		return userIds
	}

	rowsB, err := db.Query(
		"SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id",
	)

	if err != nil {
		return userIds
	}

	defer rowsB.Close()
	for rowsB.Next() {
		var userId int
		var login string
		var lastLoginId int

		if err := rowsB.Scan(&userId, &login, &lastLoginId); err != nil {
			return userIds
		}

		var count int

		err = db.QueryRow(
			"SELECT COUNT(1) AS cnt FROM login_log WHERE user_id = ? AND ? < id",
			userId, lastLoginId,
		).Scan(&count)

		if err != nil {
			return userIds
		}

		if UserLockThreshold <= count {
			userIds = append(userIds, login)
		}
	}
	if err := rowsB.Err(); err != nil {
		return userIds
	}

	return userIds
}
