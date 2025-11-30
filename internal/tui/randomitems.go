package tui

import (
	"math/rand"
	"strings"
	"sync"
	"time"
)

type randomItemGenerator struct {
	categoryWords []string
	emailHandles  []string
	mtx           *sync.Mutex
}

func (r *randomItemGenerator) reset() {
	r.mtx = &sync.Mutex{}

	r.categoryWords = []string{
		"personal",
		"work",
		"finance",
		"family",
		"shared",
		"vault",
		"banking",
		"cards",
		"cloud",
		"servers",
		"production",
		"staging",
		"dev",
		"notes",
		"archive",
		"billing",
		"security",
		"social",
		"infra",
		"ssh",
		"admin",
		"support",
		"legal",
		"medical",
		"backup",
	}

	r.emailHandles = []string{
		"alex",
		"casey",
		"dev",
		"eng",
		"finance",
		"info",
		"it",
		"jo",
		"kelly",
		"ops",
		"root",
		"sam",
		"security",
		"service",
		"team",
		"user",
	}
}

func (r *randomItemGenerator) next() item {
	if r.mtx == nil {
		r.reset()
	}

	r.mtx.Lock()
	defer r.mtx.Unlock()

	return item{
		name:      r.randomName(),
		secret:    r.randomSecret(),
		otp:       rand.Intn(2) == 0,
		updatedAt: time.Now().Add(-time.Duration(rand.Intn(72)) * time.Hour),
	}
}

func (r *randomItemGenerator) randomName() string {
	linesCount := rand.Intn(3) + 1
	lines := make([]string, linesCount)
	for i := 0; i < linesCount; i++ {
		if i == linesCount-1 {
			lines[i] = r.randomEmail()
			continue
		}
		lines[i] = r.randomCategoryLine()
	}
	return strings.Join(lines, "\n")
}

func (r *randomItemGenerator) randomCategoryLine() string {
	wordCount := rand.Intn(3) + 1
	words := make([]string, wordCount)
	for i := 0; i < wordCount; i++ {
		words[i] = r.categoryWords[rand.Intn(len(r.categoryWords))]
	}
	return strings.Join(words, " ")
}

func (r *randomItemGenerator) randomEmail() string {
	localLen := rand.Intn(6) + 6 // 6-11 characters
	local := make([]byte, localLen)
	alpha := "abcdefghijklmnopqrstuvwxyz0123456789"
	for i := 0; i < localLen; i++ {
		local[i] = alpha[rand.Intn(len(alpha))]
	}

	// Occasionally prefix with a handle for more variety.
	if rand.Intn(2) == 0 {
		handle := r.emailHandles[rand.Intn(len(r.emailHandles))]
		return handle + "+" + string(local) + "@example.com"
	}

	return string(local) + "@example.com"
}

func (r *randomItemGenerator) randomSecret() string {
	const length = 10
	chars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	secret := make([]rune, length)
	for i := range secret {
		secret[i] = chars[rand.Intn(len(chars))]
	}
	return string(secret)
}
