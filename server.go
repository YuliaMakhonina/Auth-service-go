package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"net/http"
	"os"
	"time"
)

type Tokens struct {
	User_id string `form:"user_id"`
	Access string `form:"access"`
	Refresh string `form:"refresh"`
	Ip string `form:"ip"`
}

type IpId struct {
	Id primitive.ObjectID `bson:"_id"`
	Ip string `bson:"ip"`
}

type AuthTokens struct {
	Access string `form:"access"`
	Refresh string `form:"refresh"`
}

// todo: get from config
var secret = []byte("fllkhdfdf")
var collection *mongo.Collection;
var client *mongo.Client
var ctx context.Context;

func main() {
	r := gin.Default()

	authorized := r.Group("/")
	authorized.Use(ParseAccessTokenMiddleWare())
	collection, client, ctx = getDBCollection("test", "tokens")
	{
		authorized.GET("/refreshToken", refreshToken)
		authorized.GET("/deleteAll", deleteAllRefreshTokens)
		authorized.GET("/deleteRefresh", deleteRefreshToken)
		authorized.GET("/getIpsIds", getIdsAdIps)
	}

	r.GET("/getTokens", getAccessRefreshTokens)

	// Disconnect DB
	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			panic(err)
		}
		fmt.Println("Connection to MongoDB closed.")
	}()
	port := os.Args[len(os.Args)-1]
	r.Run(fmt.Sprintf(":%s", port)) // listen and serve on 0.0.0.0:8080
}

func getDBCollection(name string, collectionName string) (*mongo.Collection, *mongo.Client, context.Context) {
	//ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
ctx := context.TODO()
	// Create client
	mongoConnectString := "mongodb+srv://JKXCxGiSWYLsvzsT:JKXCxGiSWYLsvzsT@cluster0.x6jxq.mongodb.net"
	client, err := mongo.NewClient(options.Client().ApplyURI(mongoConnectString))
	if err != nil {
		panic(err)
	}
	// Create connect
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println("Create connect")
		panic(err)
	}
	// Check the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		fmt.Println("Check the connection")
		panic(err)
	}

	fmt.Println("Connected to MongoDB!")

	collection := client.Database(name).Collection(collectionName)
	if ctx.Err() != nil {
		fmt.Println("ctx.Err() is not null")
		panic(ctx.Err())
	}
	return collection, client, ctx
}

func getAccessRefreshTokens(c * gin.Context) {
	queryValueId := c.Request.URL.Query().Get("user_id")

	// Create access token
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().UTC().Unix() + 1000*60*60*24,
		Issuer:    queryValueId,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := accessToken.SignedString(secret)
	fmt.Println(tokenString, err, secret)

	// Create refresh token
	refreshBase64, err := generateBase64String(32)
	if err != nil {
		log.Fatal(err)
	}

	refresh, err := HashPassword(refreshBase64)
	if err != nil {
		log.Fatal(err)
	}

	// Create tokens interface object
	tokens := Tokens{queryValueId, tokenString, refresh, c.ClientIP()}

	// Insert tokens in DB
	insertResult, err := collection.InsertOne(context.TODO(), tokens)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Inserted a single document: ", insertResult.InsertedID)

	c.JSON(200, AuthTokens{tokenString, refreshBase64})
}

func refreshToken(c * gin.Context) {
	jwtClaims := getClaims(c.MustGet("jwtParsed").(*jwt.Token))
	if jwtClaims == nil {
		log.Fatal()
	}

	refreshToken := c.Request.URL.Query().Get("refresh")

	var foundToken Tokens

	_ = (collection.FindOne(ctx, bson.M{"access": c.Request.URL.Query().Get("access")})).Decode(&foundToken)
	fmt.Println(foundToken)

	if CheckPasswordHash(refreshToken, foundToken.Refresh) {
		opts := options.Update().SetUpsert(true)
		filter := bson.M{"access": c.Request.URL.Query().Get("access")}

		// Create access token
		accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwtClaims)
		tokenString, err := accessToken.SignedString(secret)
		fmt.Println(tokenString, err)

		// Create refresh token
		refreshBase64, err := generateBase64String(32)
		if err != nil {
			log.Fatal(err)
		}

		refresh, err := HashPassword(refreshBase64)
		if err != nil {
			log.Fatal(err)
		}
		update := bson.D{{"$set", bson.M{"access": tokenString, "refresh": refresh}}}
		result, err := collection.UpdateOne(ctx, filter, update, opts)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(result)

		c.JSON(200, AuthTokens{tokenString, refreshBase64})
	} else {
		fmt.Println(refreshToken)
		fmt.Println(foundToken.Refresh)
		c.String(403, "wrong data")
	}
}

func getIdsAdIps(c *gin.Context) {
	jwtParsedClaims := getClaims(c.MustGet("jwtParsed").(*jwt.Token))

	cursor, err := collection.Find(ctx, bson.M{"user_id": jwtParsedClaims["iss"]})
	if err != nil {
		fmt.Println("error while getting tokens ids, ips")
		log.Fatal(err)
	}
	var tokens []IpId
	if err = cursor.All(ctx, &tokens); err != nil {
		fmt.Println("couldn't parse cursor")
		log.Fatal(err)
	}
	fmt.Println(tokens)

	c.JSON(200, tokens)
}

func deleteRefreshToken(c * gin.Context) {
	collection, client, ctx := getDBCollection("test", "tokens")
	idHex := c.Request.URL.Query().Get("id")

	jwtParsedClaims := getClaims(c.MustGet("jwtParsed").(*jwt.Token))
	if jwtParsedClaims == nil {
		log.Fatal()
	}

	objectId, err := primitive.ObjectIDFromHex(idHex)
	if err != nil {
		log.Fatal(err)
	}

	filter := bson.M{"_id": objectId}
	var foundAccess Tokens
	_ = (collection.FindOne(ctx, filter)).Decode(&foundAccess)

	if foundAccess.User_id == jwtParsedClaims["iss"] {
		deletedResult, err := collection.DeleteOne(ctx, bson.M{"_id": objectId})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("deletedResult", deletedResult)
		c.String(200, "Success")
	} else {
		c.String(403, "You can delete only yours tokens")
	}

	// Disconnect DB
	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			panic(err)
		}
		fmt.Println("Connection to MongoDB closed.")
	}()
}

func deleteAllRefreshTokens(c * gin.Context) {
	jwtParsedClaims := getClaims(c.MustGet("jwtParsed").(*jwt.Token))
	if jwtParsedClaims == nil {
		log.Fatal()
	}

	filter := bson.M{"user_id": jwtParsedClaims["iss"].(string)}
	deletedResult, err := collection.DeleteMany(ctx, filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("deletedResult", deletedResult)
	c.String(200, "Success")
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func getClaims(jwtToken *jwt.Token) (jwt.MapClaims) {
	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok && jwtToken.Valid {
		return claims
	} else {
		return nil
	}
}

func generateBase64String(size int) (string, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	encoded := base64.URLEncoding.EncodeToString(b)
	return encoded, nil
}

func ParseAccessTokenMiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwtToken := c.Request.URL.Query().Get("access")
		jwtParsed, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		},
		)
		if err != nil {
			fmt.Println(err)
			c.String(403, "Wrong data")
		} else {
			c.Set("jwtParsed", jwtParsed)
			c.Next()
		}
	}
}

func timeOutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done := make(chan bool)
		ctx, cancelFunc := context.WithTimeout(r.Context(), time.Second*1)
		defer cancelFunc()
		go func() {
			next.ServeHTTP(w, r)
			close(done)
		}()
		select {
		case <-done:
			return
		case <-ctx.Done():
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message": "handled time out"}`))
		}
	})

}
