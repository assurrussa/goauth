package confirmationcode

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
)

func Generate() (string, error) {
	var n uint32
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		return "", err
	}

	return fmt.Sprintf("%06d", n%1000000), nil
}

func Normalize(input string) string {
	s := strings.TrimSpace(input)

	var digits []rune
	for _, r := range s {
		if !unicode.IsDigit(r) {
			continue
		}

		d := int(r - '0')
		if d < 0 || d > 9 {
			switch r {
			case '０', '１', '２', '３', '４', '５', '６', '７', '８', '９':
				d = int(r - '０')
			default:
				continue
			}
		}
		digits = append(digits, rune('0'+d))
	}

	code := string(digits)
	if len(code) > 6 {
		code = code[:6]
	}

	return code
}
