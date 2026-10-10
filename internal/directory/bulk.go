package directory

import (
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// GetSampleCSV returns a documented CSV template for onboarding users
func GetSampleCSV() string {
	return `sAMAccountName,GivenName,Surname,Email,Department,JobTitle,Password,GlobalGroups
m.muster,Max,Muster,m.muster@corp.local,Finanzen,Senior Controller,P@ssw0rd2026!,G_Finanzen_Mitarbeiter;G_Controlling
s.becker,Sophie,Becker,s.becker@corp.local,IT,DevOps Engineer,,G_IT_Admin;G_DEV_Argus
l.schmidt,Lukas,Schmidt,l.schmidt@corp.local,HR,HR Specialist,Start2026#Secure,G_HR_Mitarbeiter
`
}

func generateRandomPassword(length int) string {
	const charset = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*"
	res := make([]byte, length)
	for i := range res {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		res[i] = charset[n.Int64()]
	}
	return string(res) + "1Aa!"
}

// BulkImportUsers processes CSV text, validates inputs, creates accounts, and assigns role groups
func (m *Manager) BulkImportUsers(csvData string, actor ActorInfo) (*BulkImportResult, error) {
	reader := csv.NewReader(strings.NewReader(csvData))
	reader.TrimLeadingSpace = true
	// Support semicolon or comma delimiter
	if strings.Contains(csvData, ";") && !strings.Contains(csvData, ",") {
		reader.Comma = ';'
	}

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("CSV-Header konnte nicht gelesen werden: %w", err)
	}

	colMap := make(map[string]int)
	for idx, col := range header {
		colMap[strings.ToLower(strings.TrimSpace(col))] = idx
	}

	// Verify required columns
	reqCols := []string{"samaccountname", "givenname", "surname"}
	for _, req := range reqCols {
		if _, ok := colMap[req]; !ok {
			return nil, fmt.Errorf("erforderliche CSV-Spalte fehlt: %s", req)
		}
	}

	var results []BulkImportRow
	successCount := 0
	failureCount := 0
	rowNum := 1

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		rowNum++
		if err != nil {
			results = append(results, BulkImportRow{
				RowNumber:    rowNum,
				Success:      false,
				ErrorMessage: fmt.Sprintf("CSV-Parsing-Fehler in Zeile %d: %v", rowNum, err),
			})
			failureCount++
			continue
		}

		getVal := func(colName string) string {
			if idx, ok := colMap[colName]; ok && idx < len(record) {
				return strings.TrimSpace(record[idx])
			}
			return ""
		}

		sam := getVal("samaccountname")
		givenName := getVal("givenname")
		surname := getVal("surname")
		mail := getVal("email")
		if mail == "" {
			mail = getVal("mail")
		}
		dept := getVal("department")
		title := getVal("jobtitle")
		if title == "" {
			title = getVal("title")
		}
		pwd := getVal("password")
		groupStr := getVal("globalgroups")
		if groupStr == "" {
			groupStr = getVal("groups")
		}

		row := BulkImportRow{
			RowNumber:      rowNum,
			SAMAccountName: sam,
			GivenName:      givenName,
			Surname:        surname,
			Email:          mail,
			Department:     dept,
			JobTitle:       title,
		}

		// Validation
		if sam == "" || givenName == "" || surname == "" {
			row.Success = false
			row.ErrorMessage = "SAMAccountName, GivenName und Surname dürfen nicht leer sein"
			results = append(results, row)
			failureCount++
			continue
		}

		if len(sam) > MaxSAMLength {
			row.Success = false
			row.ErrorMessage = fmt.Sprintf("sAMAccountName überschreitet maximal 64 Zeichen (Länge: %d)", len(sam))
			results = append(results, row)
			failureCount++
			continue
		}

		if pwd == "" {
			pwd = generateRandomPassword(12)
			row.Password = pwd
		}

		// Parse role groups (semicolon or comma separated)
		var roleGroups []string
		if groupStr != "" {
			parts := strings.FieldsFunc(groupStr, func(r rune) bool {
				return r == ';' || r == ','
			})
			for _, p := range parts {
				cleanG := strings.TrimSpace(p)
				if cleanG != "" {
					roleGroups = append(roleGroups, cleanG)
				}
			}
		}
		row.GlobalGroups = roleGroups

		// Check if user already exists
		existing, _ := m.activeProvider().GetUser(sam)
		if existing != nil {
			row.Success = false
			row.ErrorMessage = fmt.Sprintf("Benutzer '%s' existiert bereits im AD/Samba", sam)
			results = append(results, row)
			failureCount++
			continue
		}

		// Create user
		createInput := CreateADUserInput{
			SAMAccountName: sam,
			GivenName:      givenName,
			Surname:        surname,
			DisplayName:    fmt.Sprintf("%s %s", givenName, surname),
			Mail:           mail,
			Password:       pwd,
			Department:     dept,
			Title:          title,
			Enabled:        true,
			RoleGroups:     roleGroups,
		}

		_, err = m.CreateUser(createInput, actor)
		if err != nil {
			row.Success = false
			row.ErrorMessage = fmt.Sprintf("Erstellung fehlgeschlagen: %v", err)
			results = append(results, row)
			failureCount++
			continue
		}

		// Assign groups
		for _, grpName := range roleGroups {
			_ = m.AddMemberToGroup(grpName, sam, actor)
		}

		row.Success = true
		results = append(results, row)
		successCount++
	}

	return &BulkImportResult{
		TotalProcessed: len(results),
		SuccessCount:   successCount,
		FailureCount:   failureCount,
		Results:        results,
	}, nil
}
