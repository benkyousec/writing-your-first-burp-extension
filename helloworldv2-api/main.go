package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

var SECRET_KEY = "mambo-mambo-omatsuri-mambo"
var uniqueReferences = make(map[string]struct{})

type Env struct {
	db *sql.DB
}

type RequestId struct {
	Id string `json:"id"`
}

type Quote struct {
	Id   string `json:"id"`
	Text string `json:"text"`
}

func (e *Env) GetQuotes(c *gin.Context) {
	rows, err := e.db.Query("SELECT * FROM quote")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "Internal server error",
		})
		return
	}
	defer rows.Close()

	var quotes []Quote
	for rows.Next() {
		var quote Quote
		if err := rows.Scan(&quote.Id, &quote.Text); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Database failed",
			})
			return
		}
		quotes = append(quotes, quote)
	}

	if err := rows.Err(); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Database failed",
		})
	}

	c.JSON(http.StatusOK, quotes)
}

func (e *Env) GetQuote(c *gin.Context) {
	var reqId RequestId
	if err := c.BindJSON(&reqId); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	query := fmt.Sprintf("SELECT text FROM quote WHERE id=%s LIMIT 1", reqId.Id)

	var quote sql.NullString
	err := e.db.QueryRow(query).Scan(&quote)
	if err != nil || !quote.Valid {
		c.JSON(http.StatusOK, gin.H{
			"message": "No quote found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"quote": quote.String,
	})
}

func isValidTimestamp(ts string) bool {
	// golang time format ????? https://stackoverflow.com/a/69338568/17064199
	location, _ := time.LoadLocation("Asia/Singapore")
	t, err := time.ParseInLocation("02012006150405", ts, location)
	if err != nil {
		fmt.Println("timestamp parsing error: ", err)
		return false
	}

	now := time.Now().In(location)
	diff := now.Sub(t)
	if diff < 0 {
		diff = -diff
	}

	return diff <= 10*time.Second
}

func isUniqueRef(ref string) bool {
	_, exists := uniqueReferences[ref]
	if !exists {
		uniqueReferences[ref] = struct{}{}
		return true
	}
	return false
}

func verifySignature(token string, data []byte) (bool, error) {
	tokens := strings.Split(token, ".")
	if len(tokens) != 3 {
		return false, errors.New("jws: invalid token received, token needs 3 parts")
	}
	payload := fmt.Sprintf("%s.%s", tokens[0], tokens[1])
	mac := hmac.New(sha256.New, []byte(SECRET_KEY))
	mac.Write([]byte(payload))
	digest := mac.Sum(nil)

	computedHmac := base64.RawStdEncoding.EncodeToString(digest)
	fmt.Println("computedHmac: " + computedHmac)
	fmt.Println("tokens[2]: " + tokens[2])

	// Match signature
	if computedHmac != tokens[2] {
		return false, nil
	}

	// Verify the body
	decodedPayload, err := base64.RawStdEncoding.DecodeString(tokens[1])
	if err != nil {
		return false, errors.New("jws: invalid payload in token")
	}

	// // Minify the request body
	// var requestBody bytes.Buffer
	// if err := json.Compact(&requestBody, data); err != nil {
	// 	return false, errors.New("jws: invalid JSON in body")
	// }
	fmt.Println("Decoded payload from token: ", string(decodedPayload))
	fmt.Println("Payload from request: ", string(data))

	if bytes.Equal(decodedPayload, data) {
		return true, nil
	}

	return false, nil
}

// middleware
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		ts := c.GetHeader("Timestamp")
		ref := c.GetHeader("Ref")
		sig := c.GetHeader("Signature")

		if ts == "" || ref == "" || sig == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"message": "Missing headers",
			})
			return
		}

		// Verify Timestamp
		if !isValidTimestamp(ts) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"message": "Invalid timestamp",
			})
			return
		}
		// Verify unique Ref
		if !isUniqueRef(ref) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"message": "Ref not unique",
			})
			return
		}

		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"message": "Could not read request body",
			})
			return
		}

		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// minify the request
		var data bytes.Buffer
		if err := json.Compact(&data, bodyBytes); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"message": "Invalid JSON marshal",
			})
			return
		}
		// Verify Signature
		isVerified, err := verifySignature(sig, data.Bytes())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"message": err,
			})
			return
		}
		if !isVerified {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "Invalid signature",
			})
			return
		}
		c.Next()
	}
}

func main() {
	db, err := sql.Open("sqlite3", "file:test.db")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	env := &Env{db: db}

	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	router.GET("/quotes", env.GetQuotes)

	authorized := router.Group("/")
	authorized.Use(AuthRequired())
	{
		authorized.POST("/quote", env.GetQuote)
	}

	router.Run(":1337") // listen and serve on 0.0.0.0:1337
}
