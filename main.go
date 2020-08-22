package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"github.com/twinj/uuid"
)

var (
	Router      = gin.Default()
	RedisClient *redis.Client
)

type User struct {
	ID       uint64
	Username string
	Password string
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

type Todo struct {
	UserID uint64 `json:"user_id"`
	Title  string `json:"title"`
}

type AccessDetails struct {
	AccessUuid string
	UserId     uint64
}

var user = User{
	ID:       1,
	Username: "username",
	Password: "password",
}

func main() {
	InitRedis()

	Router.POST("/login", Login)
	Router.POST("/todo", CreateTodo)
	Router.POST("/logout", Logout)

	log.Fatal(Router.Run(":8080"))
}

func InitRedis() {
	dsn := "localhost:6379"

	RedisClient = redis.NewClient(&redis.Options{
		Addr: dsn, //redis host
	})

	res, err := RedisClient.Ping().Result()

	println(res)

	if err != nil {
		panic(err)
	}
}

func Login(c *gin.Context) {
	var u User

	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid jsson provided!")
		return
	}

	if user.Username != u.Username || user.Password != u.Password {
		c.JSON(http.StatusUnauthorized, "Please provide valid login details")
		return
	}

	token, err := CreateToken(user.ID)

	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	saveErr := CreateAuth(user.ID, token)

	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
	}

	c.JSON(http.StatusOK, token)
}

func Logout(c *gin.Context) {
	au, err := ExtractTokenMetadata(c.Request)

	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	deleted, delErr := DeleteAuth(au.AccessUuid)

	if delErr != nil || deleted == 0 {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	c.JSON(http.StatusOK, "Successfully logged out!")
}

func DeleteAuth(givenUuid string) (int64, error) {
	deleted, err := RedisClient.Del(givenUuid).Result()

	if err != nil {
		return 0, err
	}

	return deleted, nil
}

func CreateTodo(c *gin.Context) {
	var td *Todo

	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}

	tokenAuth, err := ExtractTokenMetadata(c.Request)

	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	userId, err := FetchAuth(tokenAuth)

	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	td.UserID = userId

	c.JSON(http.StatusCreated, td)
}

func FetchAuth(authD *AccessDetails) (uint64, error) {
	userid, err := RedisClient.Get(authD.AccessUuid).Result()

	if err != nil {
		return 0, err
	}

	userID, _ := strconv.ParseUint(userid, 10, 64)
	return userID, nil
}

func ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {
	token, err := VerifyToken(r)

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if ok && token.Valid {
		accessUuidd, ok := claims["access_uuid"].(string)

		if !ok {
			return nil, err
		}

		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)

		if err != nil {
			return nil, err
		}

		return &AccessDetails{
			AccessUuid: accessUuidd,
			UserId:     userId,
		}, nil
	}

	return nil, err
}

//whether it is still useful or it has expired
func TokenValid(r *http.Request) error {
	token, err := VerifyToken(r)

	if err != nil {
		return err
	}

	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}

	return nil
}

func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenStr := strings.Split(r.Header.Get("Authorization"), " ")[1]

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		//make sure that the token method conform to SigningMethodHMAC

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

//saving JWTs metadata
func CreateAuth(userid uint64, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0) //converting unix to UTC (to time object)
	rt := time.Unix(td.RtExpires, 0)

	now := time.Now()

	errAccess := RedisClient.Set(td.AccessUuid, strconv.Itoa(int(userid)), at.Sub(now)).Err()

	if errAccess != nil {
		return errAccess
	}

	errRefresh := RedisClient.Set(td.RefreshUuid, strconv.Itoa(int(userid)), rt.Sub(now)).Err()

	if errRefresh != nil {
		return errRefresh
	}

	return nil
}

func CreateToken(userid uint64) (*TokenDetails, error) {
	td := &TokenDetails{}

	td.AtExpires = time.Now().Add(15 * time.Minute).Unix()
	td.AccessUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(7 * 24 * time.Hour).Unix()
	td.RefreshUuid = uuid.NewV4().String()

	var err error

	//Creating access token
	os.Setenv("ACCESS_SECRET", "dajasdasda")

	atClaims := jwt.MapClaims{}

	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = userid
	atClaims["exp"] = td.AtExpires

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))

	if err != nil {
		return nil, err
	}

	//Creating refresh token
	rtClaims := jwt.MapClaims{}

	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = userid
	rtClaims["exp"] = td.RtExpires

	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_TOKEN")))

	if err != nil {
		return nil, err
	}

	return td, nil
}

// func CreateToken(userid uint64) (string, error) {
// 	var err error

// 	os.Setenv("ACCESS_SECRET", "dasdoasdasoi") //this should be in an env file

// 	atClaims := jwt.MapClaims{}

// 	atClaims["authorized"] = true
// 	atClaims["user_id"] = userid
// 	atClaims["exp"] = time.Now().Add(15 * time.Minute).Unix()

// 	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

// 	token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))

// 	if err != nil {
// 		return "", err
// 	}

// 	return token, nil
// }
