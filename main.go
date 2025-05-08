package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// Models
type User struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Username          string             `json:"username" binding:"required"`
	Email             string             `json:"email" binding:"required,email"`
	Password          string             `json:"password,omitempty" binding:"required,min=8"`
	CreatedAt         time.Time          `json:"createdAt,omitempty"`
	QuizzesTaken      int                `json:"quizzesTaken"`
	QuizzesCreated    int                `json:"quizzesCreated"`
	TotalPoints       int                `json:"totalPoints"`
	AverageScore      float64            `json:"averageScore"`
	HighestScore      int                `json:"highestScore"`
	HighestPercentage float64            `json:"highestPercentage"`
}

type Quiz struct {
	ID           primitive.ObjectID   `bson:"_id,omitempty" json:"id,omitempty"`
	QuizCode     string               `bson:"quizCode" json:"quizCode"`
	Title        string               `json:"title" binding:"required"`
	Description  string               `json:"description"`
	HostedBy     primitive.ObjectID   `json:"hostedBy" binding:"required"`
	CreatedAt    time.Time            `json:"createdAt,omitempty"`
	UpdatedAt    time.Time            `json:"updatedAt,omitempty"`
	Questions    []primitive.ObjectID `json:"questions,omitempty"`
	IsPublic     bool                 `json:"isPublic"`
	Category     string               `json:"category"`
	Difficulty   string               `json:"difficulty"`
	TimeLimit    int                  `json:"timeLimit" binding:"required,min=1"`
	AttemptCount int                  `json:"attemptCount"`
	AvgScore     float64              `json:"avgScore"`
}

type Question struct {
	ID                 primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	QuizID             primitive.ObjectID `json:"quizid" binding:"required"`
	QuestionText       string             `json:"questionText" binding:"required"`
	Options            []string           `json:"options" binding:"required,min=2"`
	CorrectAnswerIndex int                `json:"correctAnswerIndex" binding:"required"`
	ExplanationText    string             `json:"explanationText"`
	CreatedAt          time.Time          `json:"createdAt,omitempty"`
}

type QuizWithQuestions struct {
	Quiz      Quiz       `json:"quiz"`
	Questions []Question `json:"questions"`
}

type Submission struct {
	UserID      primitive.ObjectID `json:"userId" binding:"required"`
	QuizID      primitive.ObjectID `json:"quizid" binding:"required"`
	Answers     []int              `json:"answers" binding:"required"`
	SubmittedAt time.Time          `json:"submittedAt"`
}

type QuizResult struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserID      primitive.ObjectID `json:"userId"`
	QuizID      primitive.ObjectID `json:"quizid"`
	Score       int                `json:"score"`
	TotalScore  int                `json:"totalScore"`
	Percentage  float64            `json:"percentage"`
	SubmittedAt time.Time          `json:"submittedAt"`
	Answers     []int              `json:"answers"`
}

type UserResponse struct {
	ID                primitive.ObjectID `json:"id"`
	Username          string             `json:"username"`
	Email             string             `json:"email"`
	QuizzesTaken      int                `json:"quizzesTaken"`
	QuizzesCreated    int                `json:"quizzesCreated"`
	AverageScore      float64            `json:"averageScore"`
	HighestScore      int                `json:"highestScore"`
	HighestPercentage float64            `json:"highestPercentage"`
}

type UserStats struct {
	TotalQuizzesTaken   int            `json:"totalQuizzesTaken"`
	TotalQuizzesCreated int            `json:"totalQuizzesCreated"`
	TotalPoints         int            `json:"totalPoints"`
	AverageScore        float64        `json:"averageScore"`
	HighestScore        int            `json:"highestScore"`
	HighestPercentage   float64        `json:"highestPercentage"`
	RecentResults       []QuizResult   `json:"recentResults"`
	RecentQuizzes       []Quiz         `json:"recentQuizzes"`
	CategoryBreakdown   map[string]int `json:"categoryBreakdown"`
	ScoreDistribution   map[string]int `json:"scoreDistribution"`
}

type QuizSearchParams struct {
	Query      string `form:"q"`
	Category   string `form:"category"`
	Difficulty string `form:"difficulty"`
	SortBy     string `form:"sort_by"`
	Order      string `form:"order"`
	Limit      int    `form:"limit"`
	Page       int    `form:"page"`
}

type LeaderboardEntry struct {
	UserID      primitive.ObjectID `json:"userId"`
	Username    string             `json:"username"`
	Score       int                `json:"score"`
	TotalScore  int                `json:"totalScore"`
	Percentage  float64            `json:"percentage"`
	SubmittedAt time.Time          `json:"submittedAt"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Global variables
var (
	userCollection     *mongo.Collection
	quizCollection     *mongo.Collection
	questionCollection *mongo.Collection
	resultCollection   *mongo.Collection
	ctx                = context.Background()
	jwtSecret          = []byte(os.Getenv("JWT_SECRET"))
)

// Middleware
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		userID, err := primitive.ObjectIDFromHex(claims["userId"].(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			c.Abort()
			return
		}

		c.Set("userId", userID)
		c.Next()
	}
}

// Utility functions
func generateQuizCode() string {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 6)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Handlers
func register(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if email or username exists
	var existingUser User
	err := userCollection.FindOne(ctx, bson.M{
		"$or": []bson.M{
			{"email": user.Email},
			{"username": user.Username},
		},
	}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email or username already exists"})
		return
	}

	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user.Password = hashedPassword
	user.CreatedAt = time.Now()
	user.ID = primitive.NewObjectID()

	_, err = userCollection.InsertOne(ctx, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": user.ID.Hex(),
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	userResponse := UserResponse{
		ID:                user.ID,
		Username:          user.Username,
		Email:             user.Email,
		QuizzesTaken:      user.QuizzesTaken,
		QuizzesCreated:    user.QuizzesCreated,
		AverageScore:      user.AverageScore,
		HighestScore:      user.HighestScore,
		HighestPercentage: user.HighestPercentage,
	}

	c.JSON(http.StatusCreated, gin.H{
		"user":  userResponse,
		"token": tokenString,
	})
}

func login(c *gin.Context) {
	var loginReq LoginRequest
	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	err := userCollection.FindOne(ctx, bson.M{"email": loginReq.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if !checkPasswordHash(loginReq.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": user.ID.Hex(),
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	userResponse := UserResponse{
		ID:                user.ID,
		Username:          user.Username,
		Email:             user.Email,
		QuizzesTaken:      user.QuizzesTaken,
		QuizzesCreated:    user.QuizzesCreated,
		AverageScore:      user.AverageScore,
		HighestScore:      user.HighestScore,
		HighestPercentage: user.HighestPercentage,
	}

	c.JSON(http.StatusOK, gin.H{
		"user":  userResponse,
		"token": tokenString,
	})
}

func createQuiz(c *gin.Context) {
	userID := c.MustGet("userId").(primitive.ObjectID)
	var quizWithQuestions QuizWithQuestions
	if err := c.ShouldBindJSON(&quizWithQuestions); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate questions
	for _, question := range quizWithQuestions.Questions {
		if len(question.Options) < 2 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Each question must have at least 2 options"})
			return
		}
		if question.CorrectAnswerIndex < 0 || question.CorrectAnswerIndex >= len(question.Options) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid correct answer index"})
			return
		}
	}

	// Create quiz
	quiz := quizWithQuestions.Quiz
	quiz.ID = primitive.NewObjectID()
	quiz.QuizCode = generateQuizCode()
	quiz.HostedBy = userID
	quiz.CreatedAt = time.Now()
	quiz.UpdatedAt = time.Now()

	// Insert questions
	questionIDs := make([]primitive.ObjectID, len(quizWithQuestions.Questions))
	for i, q := range quizWithQuestions.Questions {
		q.ID = primitive.NewObjectID()
		q.QuizID = quiz.ID
		q.CreatedAt = time.Now()
		_, err := questionCollection.InsertOne(ctx, q)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create questions"})
			return
		}
		questionIDs[i] = q.ID
	}

	quiz.Questions = questionIDs
	_, err := quizCollection.InsertOne(ctx, quiz)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create quiz"})
		return
	}

	// Update user stats
	_, err = userCollection.UpdateOne(ctx,
		bson.M{"_id": userID},
		bson.M{"$inc": bson.M{"quizzesCreated": 1}},
	)
	if err != nil {
		log.Printf("Failed to update user stats: %v", err)
	}

	quizWithQuestions.Quiz = quiz
	c.JSON(http.StatusCreated, quizWithQuestions)
}

func getQuiz(c *gin.Context) {
	quizCode := c.Param("quizCode")
	var quiz Quiz
	err := quizCollection.FindOne(ctx, bson.M{"quizCode": quizCode}).Decode(&quiz)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Quiz not found"})
		return
	}

	var questions []Question
	cursor, err := questionCollection.Find(ctx, bson.M{"quizid": quiz.ID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch questions"})
		return
	}
	if err = cursor.All(ctx, &questions); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode questions"})
		return
	}

	quizWithQuestions := QuizWithQuestions{
		Quiz:      quiz,
		Questions: questions,
	}

	c.JSON(http.StatusOK, quizWithQuestions)
}

func submitQuiz(c *gin.Context) {
	userID := c.MustGet("userId").(primitive.ObjectID)
	var submission Submission
	if err := c.ShouldBindJSON(&submission); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var quiz Quiz
	err := quizCollection.FindOne(ctx, bson.M{"_id": submission.QuizID}).Decode(&quiz)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Quiz not found"})
		return
	}

	var questions []Question
	cursor, err := questionCollection.Find(ctx, bson.M{"quizid": quiz.ID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch questions"})
		return
	}
	if err = cursor.All(ctx, &questions); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode questions"})
		return
	}

	if len(submission.Answers) != len(questions) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid number of answers"})
		return
	}

	// Calculate score
	score := 0
	for i, answer := range submission.Answers {
		if answer == questions[i].CorrectAnswerIndex {
			score++
		}
	}

	totalScore := len(questions)
	percentage := (float64(score) / float64(totalScore)) * 100

	result := QuizResult{
		ID:          primitive.NewObjectID(),
		UserID:      userID,
		QuizID:      submission.QuizID,
		Score:       score,
		TotalScore:  totalScore,
		Percentage:  percentage,
		SubmittedAt: time.Now(),
		Answers:     submission.Answers,
	}

	_, err = resultCollection.InsertOne(ctx, result)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save result"})
		return
	}

	// Update quiz stats
	_, err = quizCollection.UpdateOne(ctx,
		bson.M{"_id": quiz.ID},
		bson.M{
			"$inc": bson.M{"attemptCount": 1},
			"$set": bson.M{
				"avgScore": (quiz.AvgScore*float64(quiz.AttemptCount) + float64(score)) / float64(quiz.AttemptCount+1),
			},
		},
	)
	if err != nil {
		log.Printf("Failed to update quiz stats: %v", err)
	}

	// Update user stats
	var user User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		log.Printf("Failed to fetch user: %v", err)
	}

	newQuizzesTaken := user.QuizzesTaken + 1
	newTotalPoints := user.TotalPoints + score
	newAverageScore := float64(newTotalPoints) / float64(newQuizzesTaken)
	newHighestScore := user.HighestScore
	newHighestPercentage := user.HighestPercentage

	if score > user.HighestScore {
		newHighestScore = score
	}
	if percentage > user.HighestPercentage {
		newHighestPercentage = percentage
	}

	_, err = userCollection.UpdateOne(ctx,
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"quizzesTaken":      newQuizzesTaken,
				"totalPoints":       newTotalPoints,
				"averageScore":      newAverageScore,
				"highestScore":      newHighestScore,
				"highestPercentage": newHighestPercentage,
			},
		},
	)
	if err != nil {
		log.Printf("Failed to update user stats: %v", err)
	}

	c.JSON(http.StatusOK, result)
}

func getUserStats(c *gin.Context) {
	userID := c.MustGet("userId").(primitive.ObjectID)
	var user User
	err := userCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	var recentResults []QuizResult
	cursor, err := resultCollection.Find(ctx, bson.M{"userId": userID}, options.Find().SetLimit(5).SetSort(bson.M{"submittedAt": -1}))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch recent results"})
		return
	}
	if err = cursor.All(ctx, &recentResults); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode recent results"})
		return
	}

	var recentQuizzes []Quiz
	cursor, err = quizCollection.Find(ctx, bson.M{"hostedBy": userID}, options.Find().SetLimit(5).SetSort(bson.M{"createdAt": -1}))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch recent quizzes"})
		return
	}
	if err = cursor.All(ctx, &recentQuizzes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode recent quizzes"})
		return
	}

	// Calculate category breakdown
	var results []QuizResult
	cursor, err = resultCollection.Find(ctx, bson.M{"userId": userID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch results for category breakdown"})
		return
	}
	if err = cursor.All(ctx, &results); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode results"})
		return
	}

	categoryBreakdown := make(map[string]int)
	for _, result := range results {
		var quiz Quiz
		err = quizCollection.FindOne(ctx, bson.M{"_id": result.QuizID}).Decode(&quiz)
		if err == nil {
			categoryBreakdown[quiz.Category]++
		}
	}

	// Calculate score distribution
	scoreDistribution := make(map[string]int)
	for _, result := range results {
		percentageRange := fmt.Sprintf("%d-%d%%", int(result.Percentage/10)*10, int(result.Percentage/10)*10+10)
		scoreDistribution[percentageRange]++
	}

	stats := UserStats{
		TotalQuizzesTaken:   user.QuizzesTaken,
		TotalQuizzesCreated: user.QuizzesCreated,
		TotalPoints:         user.TotalPoints,
		AverageScore:        user.AverageScore,
		HighestScore:        user.HighestScore,
		HighestPercentage:   user.HighestPercentage,
		RecentResults:       recentResults,
		RecentQuizzes:       recentQuizzes,
		CategoryBreakdown:   categoryBreakdown,
		ScoreDistribution:   scoreDistribution,
	}

	c.JSON(http.StatusOK, stats)
}

func searchQuizzes(c *gin.Context) {
	var params QuizSearchParams
	if err := c.ShouldBindQuery(&params); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if params.Limit == 0 {
		params.Limit = 10
	}
	if params.Page == 0 {
		params.Page = 1
	}

	filter := bson.M{"isPublic": true}
	if params.Query != "" {
		filter["$or"] = []bson.M{
			{"title": bson.M{"$regex": params.Query, "$options": "i"}},
			{"description": bson.M{"$regex": params.Query, "$options": "i"}},
		}
	}
	if params.Category != "" {
		filter["category"] = params.Category
	}
	if params.Difficulty != "" {
		filter["difficulty"] = params.Difficulty
	}

	sortField := "createdAt"
	if params.SortBy != "" {
		sortField = params.SortBy
	}
	sortOrder := -1
	if params.Order == "asc" {
		sortOrder = 1
	}

	var quizzes []Quiz
	cursor, err := quizCollection.Find(ctx,
		filter,
		options.Find().
			SetSort(bson.M{sortField: sortOrder}).
			SetSkip(int64((params.Page-1)*params.Limit)).
			SetLimit(int64(params.Limit)),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search quizzes"})
		return
	}
	if err = cursor.All(ctx, &quizzes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode quizzes"})
		return
	}

	total, err := quizCollection.CountDocuments(ctx, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count quizzes"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"quizzes": quizzes,
		"total":   total,
		"page":    params.Page,
		"limit":   params.Limit,
	})
}

func getLeaderboard(c *gin.Context) {
	quizCode := c.Param("quizCode")
	var quiz Quiz
	err := quizCollection.FindOne(ctx, bson.M{"quizCode": quizCode}).Decode(&quiz)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Quiz not found"})
		return
	}

	// Query resultCollection, sorting by score in descending order
	var results []QuizResult
	cursor, err := resultCollection.Find(ctx,
		bson.M{"quizid": quiz.ID},
		options.Find().SetSort(bson.M{"score": -1}),
	)
	if err != nil {
		log.Println("Error querying resultCollection:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch leaderboard"})
		return
	}

	// Decode the results into the results slice
	if err = cursor.All(ctx, &results); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode leaderboard"})
		return
	}

	// If necessary, sort by submittedAt in memory after sorting by score
	sort.Slice(results, func(i, j int) bool {
		if results[i].Score == results[j].Score {
			// If the scores are equal, sort by submittedAt (ascending order)
			return results[i].SubmittedAt.Before(results[j].SubmittedAt)
		}
		return results[i].Score > results[j].Score
	})

	// Prepare the leaderboard to return
	leaderboard := make([]LeaderboardEntry, 0, len(results))
	for _, result := range results {
		var user User
		err = userCollection.FindOne(ctx, bson.M{"_id": result.UserID}).Decode(&user)
		if err != nil {
			continue
		}
		leaderboard = append(leaderboard, LeaderboardEntry{
			UserID:      user.ID,
			Username:    user.Username,
			Score:       result.Score,
			TotalScore:  result.TotalScore,
			Percentage:  result.Percentage,
			SubmittedAt: result.SubmittedAt,
		})
	}

	c.JSON(http.StatusOK, leaderboard)
}




func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Initialize MongoDB
	mongoURI := os.Getenv("MONGO_URI")
	dbName := os.Getenv("DB_NAME")
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	// Initialize collections
	userCollection = client.Database(dbName).Collection("users")
	quizCollection = client.Database(dbName).Collection("quizzes")
	questionCollection = client.Database(dbName).Collection("questions")
	resultCollection = client.Database(dbName).Collection("results")

	// Initialize Gin
	r := gin.Default()

	// CORS configuration
	allowedOrigin := os.Getenv("ALLOWED_ORIGIN")
	config := cors.DefaultConfig()
	if allowedOrigin == "*" {
		config.AllowAllOrigins = true
	} else {
		config.AllowOrigins = []string{allowedOrigin}
	}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Authorization"}
	r.Use(cors.New(config))

	// Routes
	r.POST("/register", register)
	r.POST("/login", login)

	// Protected routes
	protected := r.Group("/", authMiddleware())
	protected.POST("/quizzes", createQuiz)
	protected.GET("/quizzes/:quizCode", getQuiz)
	protected.POST("/quizzes/submit", submitQuiz)
	protected.GET("/users/stats", getUserStats)
	protected.GET("/quizzes", searchQuizzes)
	protected.GET("/quizzes/:quizCode/leaderboard", getLeaderboard)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8056"
	}
	log.Fatal(r.Run(":" + port))
}
