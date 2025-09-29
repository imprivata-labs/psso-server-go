package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
	
	"github.com/twocanoes/psso-server/pkg/file"
)

type UserInfo struct {
	Username    string
	DisplayName string
	Email       string
	Groups      []string
}

func AuthenticateUser(username, password string) (*UserInfo, error) {
	// Your existing authentication logic from token.go
	switch username {
	case "jappleseed@twocanoes.com":
		// No password check for this user in original code
		return &UserInfo{
			Username:    username,
			DisplayName: "Johnny Appleseed",
			Email:       username,
			Groups:      []string{"admin", "net-admin", "software-install"},
		}, nil
		
	case "liz@twocanoes.com":
		if password == "twocanoes" {
			return &UserInfo{
				Username:    username,
				DisplayName: "Liz Appleseed", 
				Email:       username,
				Groups:      []string{"software-install", "psso-standard-users"},
			}, nil
		}
		
	case "nate@twocanoes.com":
		if password == "twocanoes" {
			return &UserInfo{
				Username:    username,
				DisplayName: "Nate Appleseed",
				Email:       username, 
				Groups:      []string{"software-install", "psso-standard-users"},
			}, nil
		}
		
	case "aaron.freimark":
		if password == "ArloPuppy0" {
			return &UserInfo{
				Username:    username,
				DisplayName: "Aaron Freimark",
				Email:       "aaron.freimark@macdemos.com",
				Groups:      []string{"software-install", "psso-standard-users"},
			}, nil
		}

	case "aaron.freimark2":
		if password == "ArloPuppy0" {
			return &UserInfo{
				Username:    username,
				DisplayName: "Alice Liddel",
				Email:       "aaron.freimark2@macdemos.com",
				Groups:      []string{"software-install", "psso-standard-users"},
			}, nil
		}
	}
	
	return nil, fmt.Errorf("invalid credentials")
}

func CreateUserSession(userInfo *UserInfo, deviceID, authMethod string) (*file.UserSession, error) {
	// Generate session ID
	sessionBytes := make([]byte, 32)
	rand.Read(sessionBytes)
	sessionID := hex.EncodeToString(sessionBytes)
	
	session := &file.UserSession{
		SessionID:   sessionID,
		Username:    userInfo.Username,
		DisplayName: userInfo.DisplayName,
		Email:       userInfo.Email,
		Groups:      userInfo.Groups,
		DeviceID:    deviceID,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour), // 24 hour session
		AuthMethod:  authMethod,
	}
	
	err := file.SaveSession(session)
	if err != nil {
		return nil, err
	}
	
	return session, nil
}

func generateAndSaveAuthCode(sessionID, clientID string) (string, error) {
	codeBytes := make([]byte, 32)
	rand.Read(codeBytes)
	code := hex.EncodeToString(codeBytes)
	
	authCode := &file.AuthCode{
		Code:      code,
		SessionID: sessionID,
		ClientID:  clientID,
		ExpiresAt: time.Now().Add(10 * time.Minute), // 10 min expiry
	}
	
	err := file.SaveAuthCode(authCode)
	return code, err
}
