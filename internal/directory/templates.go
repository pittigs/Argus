package directory

import (
	"fmt"

	"github.com/pittigs/argus/internal/audit"
)

// StandardShareTemplates returns out-of-the-box best-practice share structures
func StandardShareTemplates() []ShareTemplate {
	return []ShareTemplate{
		{
			ID:          "dept_standard",
			Name:        "Abteilung Standard (3-Stufen-Modell)",
			Description: "Best-Practice-Struktur fuer Unternehmensabteilungen mit Oeffentlich-, Team- und Vertraulich-Bereichen.",
			Category:    "Organisation",
			Folders: []ShareTemplateFolder{
				{
					Name:            "01_Oeffentlich",
					Description:     "Allgemeine Vorlagen und Richtlinien der Abteilung",
					Permissions:     []string{PermReadOnly, PermReadWrite},
					DefaultRoleTags: []string{"All", "Team"},
				},
				{
					Name:            "02_Team_Intern",
					Description:     "Taegliche Arbeitsdateien des Abteilungsteams",
					Permissions:     []string{PermReadWrite, PermReadOnly},
					DefaultRoleTags: []string{"Team"},
				},
				{
					Name:            "03_Vertraulich",
					Description:     "Geheime Strategiepapiere und Budgetplanungen",
					Permissions:     []string{PermReadWrite, PermFullControl},
					DefaultRoleTags: []string{"Leitung"},
				},
			},
		},
		{
			ID:          "project_collab",
			Name:        "Projektraum & Entwicklung",
			Description: "Struktur fuer agile Projektteams, Code-Artefakte und Dokumentation.",
			Category:    "Projekte",
			Folders: []ShareTemplateFolder{
				{
					Name:            "01_Dokumentation",
					Description:     "Konzepte, Architekturskizzen und Spezifikationen",
					Permissions:     []string{PermReadOnly, PermReadWrite},
					DefaultRoleTags: []string{"Team", "Stakeholder"},
				},
				{
					Name:            "02_Quellcode_Builds",
					Description:     "Quellcodedateien, Build-Artefakte und Skripte",
					Permissions:     []string{PermReadWrite},
					DefaultRoleTags: []string{"Entwickler"},
				},
				{
					Name:            "03_Vertraege_Budget",
					Description:     "Projektauftraege, Angebote und Budgetcontrolling",
					Permissions:     []string{PermReadWrite},
					DefaultRoleTags: []string{"Projektleitung"},
				},
			},
		},
		{
			ID:          "hr_confidential",
			Name:        "HR & Personalwesen (DSGVO-konform)",
			Description: "Strikte Trennung von Personalakten, Bewerbungen und Betriebsrichtlinien.",
			Category:    "Compliance & HR",
			Folders: []ShareTemplateFolder{
				{
					Name:            "Personalakten",
					Description:     "Hochsensible Mitarbeiterakten gemaess Art. 9 DSGVO",
					Permissions:     []string{PermReadWrite, PermFullControl},
					DefaultRoleTags: []string{"HR_Leitung"},
				},
				{
					Name:            "Bewerbermanagement",
					Description:     "Lebenslaeufe, Bewerbungen und Interview-Notizen",
					Permissions:     []string{PermReadWrite},
					DefaultRoleTags: []string{"HR_Recruiting"},
				},
				{
					Name:            "Betriebsvereinbarungen",
					Description:     "Fuer alle Mitarbeiter gueltige Betriebsvereinbarungen",
					Permissions:     []string{PermReadOnly, PermReadWrite},
					DefaultRoleTags: []string{"All", "HR_Team"},
				},
			},
		},
		{
			ID:          "finance_gobd",
			Name:        "Finanzen & Revision (GoBD/Compliance)",
			Description: "Revisionssichere Struktur fuer Buchhaltung, Belege und Pruefungsdokumente.",
			Category:    "Finanzen",
			Folders: []ShareTemplateFolder{
				{
					Name:            "01_Buchhaltung_Laufend",
					Description:     "Laufende Monatsabschluesse und Buchungsbelege",
					Permissions:     []string{PermReadWrite},
					DefaultRoleTags: []string{"Finanzen_Team"},
				},
				{
					Name:            "02_Jahresabschluss_Planung",
					Description:     "Jahresabschluesse, Steuerbilanzen und Wirtschaftspruefer-Ordner",
					Permissions:     []string{PermReadWrite, PermFullControl},
					DefaultRoleTags: []string{"Finanzen_Leitung"},
				},
				{
					Name:            "03_Revisionsarchiv_Festgeschrieben",
					Description:     "Festgeschriebene GoBD-Belege (ReadOnly fuer Pruefer)",
					Permissions:     []string{PermReadOnly, PermReadWrite},
					DefaultRoleTags: []string{"Revision", "Finanzen_Team"},
				},
			},
		},
	}
}

// GetShareTemplates lists all available templates
func (m *Manager) GetShareTemplates() []ShareTemplate {
	return StandardShareTemplates()
}

// ApplyShareTemplate instantiates a full AGDLP folder hierarchy from a template
func (m *Manager) ApplyShareTemplate(input ApplyShareTemplateInput, actor ActorInfo) (*TemplateApplyResult, error) {
	templates := StandardShareTemplates()
	var selected *ShareTemplate
	for _, t := range templates {
		if t.ID == input.TemplateID {
			selected = &t
			break
		}
	}

	if selected == nil {
		return nil, fmt.Errorf("Vorlage '%s' nicht gefunden", input.TemplateID)
	}

	cleanShare := CleanToken(input.ShareName)
	if cleanShare == "" {
		return nil, fmt.Errorf("share_name darf nicht leer sein")
	}

	var allCreatedGroups []ADGroup
	folderCount := 0

	var globalRolesToAssign []string
	if input.Department != "" {
		if roleName, err := BuildGlobalRoleGroupName(input.Department, "Mitarbeiter"); err == nil {
			globalRolesToAssign = append(globalRolesToAssign, roleName)
		}
	}

	allGroupMap := make(map[string]ADGroup)

	for _, folder := range selected.Folders {
		hasRO := false
		hasRW := false
		hasFC := false

		for _, p := range folder.Permissions {
			if p == PermReadOnly {
				hasRO = true
			}
			if p == PermReadWrite {
				hasRW = true
			}
			if p == PermFullControl {
				hasFC = true
			}
		}

		shareInput := AGDLPShareInput{
			ShareName:            cleanShare,
			FolderName:           folder.Name,
			Description:          folder.Description,
			CreateReadOnly:       hasRO,
			CreateReadWrite:      hasRW,
			CreateFullControl:    hasFC,
			AssignedGlobalGroups: globalRolesToAssign,
		}

		groups, err := m.CreateAGDLPFileShare(shareInput, actor)
		if err != nil {
			return nil, fmt.Errorf("Fehler bei Ordner '%s': %w", folder.Name, err)
		}

		for _, g := range groups {
			allCreatedGroups = append(allCreatedGroups, g)
			allGroupMap[g.Permission] = g
		}
		folderCount++
	}

	// Generate consolidated script
	scripts := GenerateACLACommands(cleanShare, "TemplateRoot", allGroupMap)

	// Audit record
	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.agdlp.template_applied",
		ResourceType:  "file_share",
		ResourceID:    cleanShare,
		Status:        "SUCCESS",
		NewValues:     fmt.Sprintf(`{"template":"%s","folders_created":%d,"groups_count":%d}`, input.TemplateID, folderCount, len(allCreatedGroups)),
		Reason:        fmt.Sprintf("AGDLP-Vorlage '%s' auf Freigabe '%s' angewendet (%d Ordner)", selected.Name, cleanShare, folderCount),
	})

	return &TemplateApplyResult{
		ShareName:      cleanShare,
		CreatedGroups:  allCreatedGroups,
		Scripts:        scripts,
		FoldersCreated: folderCount,
	}, nil
}
