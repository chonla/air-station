package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	APP_NAME    = "Air Station"
	APP_VERSION = "1.1.2"
)

type AirQualityRequest struct {
	PM1   int64 `json:"pm1"`
	PM2_5 int64 `json:"pm2.5"`
	PM10  int64 `json:"pm10"`
}

type AirQuality struct {
	Station   string
	PM1       int64
	PM2_5     int64
	PM10      int64
	Timestamp time.Time
}

type AirQualityResponse struct {
	PM1       int64 `json:"pm1"`
	PM2_5     int64 `json:"pm2.5"`
	PM10      int64 `json:"pm10"`
	Timestamp time.Time
}

func (AirQualityResponse) TableName() string {
	return "air_qualities"
}

type Station struct {
	Key    string
	Secret string
}

type AboutStationResponse struct {
	Name    string
	Version string
}

var db *gorm.DB

const TWENTY_FOUR_HOURS = 24 * time.Hour

func isAuthorizedRequest(r *http.Request) (string, bool) {
	credential := ""
	for headerName, headerValues := range r.Header {
		for _, headerValue := range headerValues {
			if headerName == "Authorization" && headerValue[0:7] == "Bearer " {
				credential = headerValue[7:]
			}
		}
	}

	plainCredential, err := b64.StdEncoding.DecodeString(credential)
	if err != nil {
		logrus.Info("Unable to decode bearer.")
		return "", false
	}

	credentialTokens := strings.Split(string(plainCredential), ":")

	var result Station
	err = db.Where("key = ? AND secret = ?", credentialTokens[0], credentialTokens[1]).
		First(&result).Error
	if err != nil {
		logrus.Info("Unable to find credential.")
		return "", false
	}
	return credentialTokens[0], true
}

func isDataAcceptable(r *http.Request) bool {
	acceptable := false
	for headerName, headerValues := range r.Header {
		for _, headerValue := range headerValues {
			if headerName == "Content-Type" && headerValue == "application/json" {
				acceptable = true
			}
		}
	}

	return acceptable
}

func getAirQualityRecords(w http.ResponseWriter, r *http.Request) {
	stationName := r.URL.Query().Get("station")

	fromTime := time.Now().Add(-1 * TWENTY_FOUR_HOURS)

	var airQualityResponse []AirQualityResponse
	if stationName != "" {
		err := db.Where("timestamp > ?", fromTime).
			Order("timestamp desc").
			Find(&airQualityResponse).Error
		if err == nil {
			err = json.NewEncoder(w).Encode(airQualityResponse)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func createAirQualityRecord(w http.ResponseWriter, r *http.Request) {
	var stationName string
	var ok bool

	// Authorize request
	if stationName, ok = isAuthorizedRequest(r); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !isDataAcceptable(r) {
		logrus.Info("Content type is not acceptable.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var report AirQualityRequest

	err := json.NewDecoder(r.Body).Decode(&report)
	if err != nil {
		logrus.Info("Unable to parse request body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	aq := AirQuality{
		PM1:       report.PM1,
		PM2_5:     report.PM2_5,
		PM10:      report.PM10,
		Timestamp: time.Now(),
		Station:   stationName,
	}
	if err = db.Create(&aq).Error; err != nil {
		logrus.Errorf("Unable to insert data: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	logrus.Infof("Incoming report from %s at %s ...", stationName, aq.Timestamp.Format("15:04:05"))
	w.WriteHeader(http.StatusCreated)
}

func setupJSONResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
}

func setupAirQualityCORS(w http.ResponseWriter, r *http.Request) {
	allowedOrigin := os.Getenv("ACCESS_CONTROL_ALLOW_ORIGIN")
	if allowedOrigin == "" {
		allowedOrigin = "*"
	}

	w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-CSRF-Token")
}

func setupAboutCORS(w http.ResponseWriter, r *http.Request) {
	allowedOrigin := os.Getenv("ACCESS_CONTROL_ALLOW_ORIGIN")
	if allowedOrigin == "" {
		allowedOrigin = "*"
	}

	w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-CSRF-Token")
}

func getAboutStation(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(AboutStationResponse{
		Name:    APP_NAME,
		Version: APP_VERSION,
	})
}

func airQualityHandler(w http.ResponseWriter, r *http.Request) {
	setupAirQualityCORS(w, r)
	setupJSONResponse(w, r)

	switch r.Method {
	case "POST":
		createAirQualityRecord(w, r)
	case "GET":
		getAirQualityRecords(w, r)
	case "OPTIONS":
		return
	// TODO:
	// case "DELETE":
	// DELETE to purge obsolete data
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	setupAboutCORS(w, r)
	setupJSONResponse(w, r)

	switch r.Method {
	case "GET":
		getAboutStation(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func main() {
	logrus.SetLevel(logrus.InfoLevel)

	port := os.Getenv("PORT")
	if port == "" {
		port = "1747"
		logrus.Info("Port is not set. Default port is used.")
	}

	logrus.Info("Initialize database connection ....")
	var err error

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logrus.Info("DATABASE_URL is not set. Default sqlite database is used.")
		db, err = gorm.Open(sqlite.Open("airstation.db"), &gorm.Config{})
	} else {
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	}

	if err != nil {
		logrus.Errorf("Unable to initialize database connection: %v", err)
		os.Exit(1)
	}

	db.AutoMigrate(&AirQuality{}, &Station{})

	http.HandleFunc("/aq", airQualityHandler)
	http.HandleFunc("/", aboutHandler)

	logrus.Info(fmt.Sprintf("Air Station Master is listening on [:%s]", port))
	http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
}
