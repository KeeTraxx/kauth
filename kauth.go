package echomultiauth

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"os"

	"github.com/dghubble/gologin"
	"github.com/dghubble/gologin/google"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"golang.org/x/oauth2"
	googleOAuth2 "golang.org/x/oauth2/google"
	g "google.golang.org/api/oauth2/v2"
)

type KAuth struct {
	e            *echo.Echo
	Logins       chan *g.Userinfoplus
	sessionStore *sessions.CookieStore
}

const (
	sessionName   = "highscore-session"
	sessionSecret = "highscore-secret-cookie-salt"
)

func New(e *echo.Echo) (kauth *KAuth) {
	kauth = &KAuth{
		e:            e,
		Logins:       make(chan *g.Userinfoplus),
		sessionStore: sessions.NewCookieStore([]byte(sessionSecret), nil),
	}

	gob.Register(&g.Userinfoplus{})

	e.POST("/logout", func(c echo.Context) error {
		//sessionStore.Destroy(c.Request(), sessionName)

		sess, _ := kauth.sessionStore.Get(c.Request(), sessionName)
		sess.Options.MaxAge = -1

		sess.Save(c.Request(), c.Response())

		return c.Redirect(http.StatusFound, "/")
	})

	kauth.setupGoogle()

	return
}

func (kauth *KAuth) setupGoogle() {
	oauth2Config := &oauth2.Config{
		ClientID:     "736599901494-vet694v3bdbum6n2bbfibdanuam6b02v.apps.googleusercontent.com",
		ClientSecret: "OVpLOVrGlQNW28S0UuApuqO4",
		RedirectURL:  getenv("BASE_URL", "http://localhost:1323") + "/google/callback",
		Endpoint:     googleOAuth2.Endpoint,
		Scopes:       []string{"profile", "email"},
	}
	stateConfig := gologin.DebugOnlyCookieConfig

	kauth.e.Any("/google/login", echo.WrapHandler(google.StateHandler(stateConfig, google.LoginHandler(oauth2Config, nil))))
	kauth.e.Any("/google/callback", echo.WrapHandler(google.StateHandler(stateConfig, google.CallbackHandler(oauth2Config, kauth.issueSessionGoogle(), nil))))

	kauth.e.GET("/profile", func(c echo.Context) error {

		session, err := kauth.sessionStore.Get(c.Request(), sessionName)

		if err != nil {
			return c.String(http.StatusInternalServerError, "500 Internal Server Error")
		}

		return c.JSON(http.StatusOK, session.Values["profile"])
	})

}

func (kauth *KAuth) issueSessionGoogle() http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		googleUser, err := google.UserFromContext(ctx)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Printf("Got userino: %+v\n", googleUser)

		// 2. Implement a success handler to issue some form of session
		session, err := kauth.sessionStore.New(req, sessionName)

		session.Values["user_id"] = googleUser.Id
		session.Values["type"] = "google"
		session.Values["profile"] = googleUser

		err = session.Save(req, w)

		if err != nil {
			fmt.Println(err)
		}

		kauth.Logins <- googleUser

		http.Redirect(w, req, "/", http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}

func (kauth *KAuth) RequiresAuth() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			session, err := kauth.sessionStore.Get(c.Request(), sessionName)
			if err != nil {
				return
			}

			fmt.Printf("%+v\n", session.Values)

			if _, ok := session.Values["user_id"]; !ok {
				return c.String(http.StatusForbidden, "403 Forbidden")
			}

			return next(c)
		}
	}
}

func (kauth *KAuth) GetUserID(c echo.Context) (string, error) {
	session, err := kauth.sessionStore.Get(c.Request(), sessionName)
	if err != nil {
		return "", fmt.Errorf("Session error")
	}

	if userID, exists := session.Values["user_id"].(string); exists {
		return userID, nil
	}
	return "", fmt.Errorf("not logged in")

}

func (kauth *KAuth) GetUser(c echo.Context) (*g.Userinfoplus, error) {
	session, err := kauth.sessionStore.Get(c.Request(), sessionName)
	if err != nil {
		return nil, fmt.Errorf("Session error")
	}

	if guser, exists := session.Values["profile"].(g.Userinfoplus); exists {
		return &guser, nil
	}
	return nil, fmt.Errorf("not logged in")

}
