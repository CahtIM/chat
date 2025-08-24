package oauth2

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/cahtio/chat/server/logs"
	"github.com/cahtio/chat/server/store"
	"github.com/cahtio/chat/server/store/types"
	"golang.org/x/crypto/bcrypt"

	firebase "firebase.google.com/go"
	gauth "firebase.google.com/go/auth"
	"github.com/cahtio/chat/server/auth"
	"google.golang.org/api/option"
)

const realName = "oauth2"

type authenticator struct {
	initialized bool
	name        string
	authClient  *gauth.Client // Firebase Auth客户端
}

func (a *authenticator) Init(jsonconf json.RawMessage, name string) error {
	// 初始化Firebase Admin SDK
	opt := option.WithCredentialsFile("./caht-7b52e-firebase-adminsdk-fbsvc-87f363c5c7.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return err
	}

	a.authClient, err = app.Auth(context.Background())
	if err != nil {
		return err
	}

	a.name = name
	a.initialized = true
	return nil
}

func (a *authenticator) IsInitialized() bool {
	return a.initialized
}

func (a *authenticator) AddRecord(rec *auth.Rec, secret []byte, remoteAddr string) (*auth.Rec, error) {
	// 实现添加记录逻辑
	return rec, nil
}

func (a *authenticator) UpdateRecord(rec *auth.Rec, secret []byte, remoteAddr string) (*auth.Rec, error) {
	// 实现更新记录逻辑
	return rec, nil
}

func (a *authenticator) Authenticate(secret []byte, remoteAddr string) (*auth.Rec, []byte, error) {
	logs.Info.Printf("Authenticate secret: %s", secret)
	// 解析Google ID Token
	firebaseIdToken := string(secret)

	logs.Info.Printf("Authenticate Unmarshal-idToken: %s", firebaseIdToken)
	// 验证Google ID Token
	token, err := a.authClient.VerifyIDToken(context.Background(), firebaseIdToken)
	if err != nil {
		logs.Info.Printf("Authenticate VerifyIDToken err : %s", err)
		return nil, nil, err
	}

	// Auth SUCCESS

	logs.Info.Printf("Authenticate VerifyIDToken Claims: %s", token.Claims)
	// 创建Firebase自定义令牌
	// customToken, err := a.authClient.CustomToken(context.Background(), token.UID)
	// if err != nil {
	// 	return nil, nil, err
	// }
	// Check token expiration time.
	uname := token.Claims["email"].(string)
	if uname == "" {
		uname = token.Claims["name"].(string)
	}
	expires := time.Unix(int64(token.Expires), 0).UTC()
	if expires.Before(time.Now().Add(1 * time.Second)) {
		return nil, nil, types.ErrExpired
	}
	uid, authLvl, _, _, err := store.Users.GetAuthUniqueRecord(a.name, uname)
	if err != nil {
		return nil, nil, err
	}
	passhash, err := bcrypt.GenerateFromPassword([]byte(token.UID), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, err
	}
	if uid.IsZero() {
		// create new user
		authLvl = auth.LevelAuth
		stringSlice := []string{
			"oauth2:" + uname,
			"email:" + token.Claims["email"].(string),
			token.Firebase.SignInProvider + ":" + token.UID,
		}
		user := types.User{
			State: types.StateOK,
			Public: map[string]any{
				"fn":    token.Claims["name"].(string),
				"photo": map[string]string{"ref": token.Claims["picture"].(string)},
			},
			Trusted: map[string]any{
				"email_verified": token.Claims["email_verified"].(bool),
			},
			Tags: stringSlice,
		}
		user.Access.Auth.UnmarshalText([]byte(types.ModeCP2PD.String()))
		// user.Access.Anon.UnmarshalText([]byte(resp.NewAcc.Anon))
		private := []string{
			"uid:" + token.UID,
		}
		u, err := store.Users.Create(&user, private)
		if err != nil {
			return nil, nil, err
		}
		uid = u.Uid()

		if err := store.Users.AddAuthRecord(uid, authLvl, a.name, uname, passhash, expires); err != nil {
			return nil, nil, err
		}
		store.Users.UpsertCred(&types.Credential{
			User:   u.Uid().String(),
			Method: a.name,
			Value:  uname,
			Done:   true,
		})
	} else {
		if err := store.Users.UpdateAuthRecord(uid, authLvl, a.name, uname, passhash, expires); err != nil {
			return nil, nil, err
		}
	}

	rec := &auth.Rec{
		Uid:       types.Uid(uid), // 将UID转换为字符串后再转换
		AuthLevel: authLvl,
		Lifetime:  auth.Duration(time.Until(expires)),
		Features:  auth.Feature(auth.FeatureValidated),
		State:     types.StateOK,
	}

	return rec, nil, nil
}

func (a *authenticator) AsTag(token string) string {
	// 实现标签转换逻辑
	return ""
}

func (a *authenticator) IsUnique(secret []byte, remoteAddr string) (bool, error) {
	// 实现唯一性检查逻辑
	return true, nil
}

func (a *authenticator) GenSecret(rec *auth.Rec) ([]byte, time.Time, error) {
	// 实现生成密钥逻辑
	return nil, time.Time{}, nil
}

func (a *authenticator) DelRecords(uid types.Uid) error {
	// 实现删除记录逻辑
	return nil
}

func (a *authenticator) RestrictedTags() ([]string, error) {
	// 实现受限标签逻辑
	return nil, nil
}

func (a *authenticator) GetResetParams(uid types.Uid) (map[string]any, error) {
	// 实现获取重置参数逻辑
	return nil, nil
}

func (a *authenticator) GetRealName() string {
	return "oauth2"
}

func init() {
	store.RegisterAuthScheme(realName, &authenticator{})
	log.Println("Register auth scheme: oauth2")
}
