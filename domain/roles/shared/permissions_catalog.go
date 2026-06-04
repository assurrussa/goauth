//nolint:nolintlint,revive // standard project naming pattern
package shared

import (
	"slices"
	"strings"
)

type PermissionCatalog struct {
	Data []PermissionDefinition
}

// PermissionDefinition describes a permission key and its default description.
type PermissionDefinition struct {
	Key         PermissionKey
	Description string
}

var defaultPermissionDefinitions = []PermissionDefinition{
	{Key: NewPermissionKey(PermissionDomainRoles, PermissionActionRead), Description: "Просмотр списка ролей и деталей"},
	{Key: NewPermissionKey(PermissionDomainRoles, PermissionActionCreate), Description: "Создание новой роли"},
	{Key: NewPermissionKey(PermissionDomainRoles, PermissionActionUpdate), Description: "Редактирование существующей роли"},
	{Key: NewPermissionKey(PermissionDomainRoles, PermissionActionDelete), Description: "Удаление роли"},
	{Key: NewPermissionKey(PermissionDomainRoles, PermissionActionAssign), Description: "Назначение ролей администраторам"},
	{Key: NewPermissionKey(PermissionDomainPermissions, PermissionActionRead), Description: "Просмотр справочника разрешений"},
	{
		Key:         NewPermissionKey(PermissionDomainPermissions, PermissionActionSync),
		Description: "Синхронизация справочника разрешений с кодовой базой",
	},
	{Key: NewPermissionKey(PermissionDomainDashboard, PermissionActionRead), Description: "Просмотр dashboard"},
	{Key: NewPermissionKey(PermissionDomainAdmins, PermissionActionRead), Description: "Просмотр админов"},
	{Key: NewPermissionKey(PermissionDomainAdmins, PermissionActionCreate), Description: "Создание нового админа"},
	{Key: NewPermissionKey(PermissionDomainAdmins, PermissionActionUpdate), Description: "Редактирование админа"},
	{Key: NewPermissionKey(PermissionDomainAdmins, PermissionActionDelete), Description: "Удаление админа"},
	{Key: NewPermissionKey(PermissionDomainOperations, PermissionActionRead), Description: "Просмотр служебных операций"},
	{Key: NewPermissionKey(PermissionDomainOperations, PermissionActionUpdate), Description: "Запуск служебных операций"},
	{Key: NewPermissionKey(PermissionDomainUsers, PermissionActionRead), Description: "Просмотр пользователя"},
	{Key: NewPermissionKey(PermissionDomainUsers, PermissionActionCreate), Description: "Создание нового пользователя"},
	{Key: NewPermissionKey(PermissionDomainUsers, PermissionActionUpdate), Description: "Редактирование пользователя"},
	{Key: NewPermissionKey(PermissionDomainUsers, PermissionActionDelete), Description: "Удаление пользователя"},
	{Key: NewPermissionKey(PermissionDomainUploads, PermissionActionRead), Description: "Просмотр файлов"},
	{Key: NewPermissionKey(PermissionDomainUploads, PermissionActionCreate), Description: "Создание нового файла"},
	{Key: NewPermissionKey(PermissionDomainUploads, PermissionActionUpdate), Description: "Редактирование файла"},
	{Key: NewPermissionKey(PermissionDomainUploads, PermissionActionDelete), Description: "Удаление файла"},
	{Key: NewPermissionKey(PermissionDomainQueues, PermissionActionRead), Description: "Просмотр очереди задач"},
	{Key: NewPermissionKey(PermissionDomainQueues, PermissionActionUpdate), Description: "Повторная отправка задач в очередь"},
	{Key: NewPermissionKey(PermissionDomainQueues, PermissionActionDelete), Description: "Удаление задач из очереди и DLQ"},
}

// DefaultPermissionDefinitions returns the whitelist of supported permissions.
func DefaultPermissionDefinitions() PermissionCatalog {
	return NewPermissionCatalog(defaultPermissionDefinitions)
}

// NewPermissionCatalog snapshots the provided definitions into a catalog.
func NewPermissionCatalog(definitions []PermissionDefinition) PermissionCatalog {
	return PermissionCatalog{Data: ClonePermissionDefinitions(definitions)}
}

// ClonePermissionDefinitions returns a detached copy of the definitions slice.
func ClonePermissionDefinitions(definitions []PermissionDefinition) []PermissionDefinition {
	if len(definitions) == 0 {
		return nil
	}

	return slices.Clone(definitions)
}

// MergePermissionDefinitions merges multiple definition sets by key.
func MergePermissionDefinitions(definitionSets ...[]PermissionDefinition) []PermissionDefinition {
	var merged []PermissionDefinition
	indexByKey := make(map[string]int)

	for _, definitions := range definitionSets {
		for _, definition := range definitions {
			if definition.Key.IsZero() {
				continue
			}

			key := definition.Key.String()
			if idx, ok := indexByKey[key]; ok {
				if strings.TrimSpace(definition.Description) != "" {
					merged[idx].Description = definition.Description
				}
				continue
			}

			indexByKey[key] = len(merged)
			merged = append(merged, PermissionDefinition{
				Key:         definition.Key,
				Description: definition.Description,
			})
		}
	}

	return merged
}

func (p PermissionCatalog) GetPermissions() []PermissionKey {
	perms := make([]PermissionKey, 0, len(p.Data))
	for _, perm := range p.Data {
		perms = append(perms, perm.Key)
	}

	return perms
}

func (p PermissionCatalog) Get(domain PermissionDomain, action PermissionAction) (PermissionDefinition, error) {
	for _, def := range p.Data {
		if def.Key.Domain == domain && def.Key.Action == action {
			return def, nil
		}
	}

	return PermissionDefinition{}, ErrPermissionNotFound
}
