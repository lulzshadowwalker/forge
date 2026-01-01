package main

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"crypto/rand"
	"encoding/base64"

	"github.com/charmbracelet/huh"
	"github.com/joho/godotenv"
)

type Forger interface {
	Run(p Project) error
	Persist() error
	SQLConfig() string
	GetVars() map[string]string
}

var (
	ErrForgePathDoesNotExist = errors.New("the specified forge path does not exist")
	ErrForgePathNotLaravel   = errors.New("the specified forge path is not a Laravel project")
	ErrForgeNoEnvFile        = errors.New("no .env file found in the specified forge path")
)

type EnvValue struct {
	Value  string
	Source string
}

type Project struct {
	Path    string
	Env     Env
	Slug    string
	EnvVars map[string]EnvValue
}

func (p *Project) Validate() error {
	if info, err := os.Stat(p.Path); os.IsNotExist(err) || !info.IsDir() {
		return ErrForgePathDoesNotExist
	}

	if info, err := os.Stat(fmt.Sprintf("%s/artisan", p.Path)); os.IsNotExist(err) || info.IsDir() {
		return ErrForgePathNotLaravel
	}

	envs := []string{".env", ".env.example"}
	found := false
	for _, env := range envs {
		if info, err := os.Stat(fmt.Sprintf("%s/%s", p.Path, env)); err == nil && !info.IsDir() {
			found = true
			break
		}
	}

	if !found {
		return ErrForgeNoEnvFile
	}

	if err := p.ParseEnvFiles(); err != nil {
		fmt.Printf("error parsing env files: %v\n", err)
		return errors.New("failed to parse env files")
	}

	return nil
}

func (p *Project) ParseEnvFiles() error {
	files := []string{".env.example", ".env"}
	for _, file := range files {
		fullPath := fmt.Sprintf("%s/%s", p.Path, file)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			envMap, err := godotenv.Read(fullPath)
			if err != nil {
				return fmt.Errorf("error reading env file %s: %w", fullPath, err)
			}

			if p.EnvVars == nil {
				p.EnvVars = make(map[string]EnvValue)
			}

			for k, v := range envMap {
				p.EnvVars[k] = EnvValue{
					Value:  v,
					Source: file,
				}
			}
		}
	}
	return nil
}

func (p *Project) HasKey(prefix string) bool {
	for k := range p.EnvVars {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}

	return false
}

type Env string

const (
	EnvProduction Env = "production"
	EnvStaging    Env = "staging"
)

func main() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("no .env file found or error loading .env file:", err)
	}

	project := Project{
		Path: os.Getenv("DEFAULT_BASE_PATH"),
		Env:  Env(EnvStaging),
	}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Project Path").
				Value(&project.Path).
				Placeholder("/path/to/project").
				SuggestionsFunc(func() []string {
					base := os.Getenv("DEFAULT_BASE_PATH")
					entries, err := os.ReadDir(base)
					if err != nil {
						fmt.Printf("error reading dir for suggestions: %v\n", err)
						return []string{}
					}

					suggestions := []string{}
					for _, entry := range entries {
						if entry.IsDir() {
							suggestions = append(suggestions, fmt.Sprintf("%s%s", base, entry.Name()))
						}
					}

					return suggestions
				}, &project.Path).
				Validate(func(v string) error {
					return project.Validate()
				}),
		),

		huh.NewGroup(
			huh.NewSelect[Env]().
				Title("Deployment Environment").
				Options(
					huh.NewOption("Production", EnvProduction),
					huh.NewOption("Staging", EnvStaging),
				).
				Value(&project.Env),
		),

		huh.NewGroup(
			huh.NewInput().
				Title("Project Slug").
				SuggestionsFunc(func() []string {
					name := strings.Split(project.Path, "/")[len(strings.Split(project.Path, "/"))-1]
					slug := strings.ToLower(fmt.Sprintf("%s_%s", strings.ReplaceAll(name, " ", "_"), string(project.Env)))
					return []string{slug}
				}, &project.Path).
				Value(&project.Slug).
				Placeholder("project_slug"),
		),
	)
	if err := form.Run(); err != nil {
		fmt.Printf("error running form: %v\n", err)
		os.Exit(1)
	}

	var forger Forger
	if project.Env == EnvProduction {
		forger = NewProductionForger(project)
	} else {
		forger = NewStagingForger(project)
	}

	if err := forger.Run(project); err != nil {
		fmt.Printf("error running forger: %v\n", err)
		os.Exit(1)
	}

	if err := forger.Persist(); err != nil {
		fmt.Printf("error persisting env file: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Environment file generated successfully.")

	fmt.Println()
	fmt.Println(forger.SQLConfig())
	fmt.Println()

	vars := forger.GetVars()
	dbName := vars["DB_DATABASE"]
	dbUser := vars["DB_USERNAME"]

	if len(dbName) > 64 {
		fmt.Printf("\nWARNING: Database name '%s' exceeds 64 characters (MySQL limit).\n", dbName)
	}
	if len(dbUser) > 32 {
		fmt.Printf("\nWARNING: Database username '%s' exceeds 32 characters (MySQL limit).\n", dbUser)
	}
}

type BaseForger struct {
	Project Project
	Vars    map[string]string
}

func NewBaseForger(p Project) *BaseForger {
	return &BaseForger{
		Vars:    make(map[string]string),
		Project: p,
	}
}

func (f *BaseForger) GetVars() map[string]string {
	return f.Vars
}

func (f *BaseForger) Run(p Project) error {
	configs := []func() (map[string]string, error){
		f.AppConfig,
		f.AWSConfig,
		f.FilesystemConfig,
		f.CacheConfig,
		f.SessionConfig,
		f.QueueConfig,
		f.BroadcastingConfig,
		f.LogConfig,
		f.RedisConfig,
		f.AppKey,
	}

	for _, fn := range configs {
		cfg, err := fn()
		if err != nil {
			return err
		}
		maps.Copy(f.Vars, cfg)
	}

	if err := f.HandleUnrecognizedVars(); err != nil {
		return err
	}

	return nil
}

func (f *BaseForger) ValidateRequired(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("this field is required")
	}

	return nil
}

func (f *BaseForger) Persist() error {
	grouped := make(map[string][]string)
	for k := range f.Vars {
		prefix := strings.Split(k, "_")[0]
		grouped[prefix] = append(grouped[prefix], k)
	}

	prefixes := make([]string, 0, len(grouped))
	for p := range grouped {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	var content strings.Builder
	for i, prefix := range prefixes {
		keys := grouped[prefix]
		sort.Strings(keys)

		for _, k := range keys {
			content.WriteString(fmt.Sprintf("%s=%s\n", k, f.Vars[k]))
		}

		if i < len(prefixes)-1 {
			content.WriteString("\n")
		}
	}

	timestamp := time.Now().Format("20060102_150405")
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	filename := fmt.Sprintf("%s/.env.g.%s", cwd, timestamp)
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(content.String())
	if err != nil {
		return fmt.Errorf("failed to write env file: %w", err)
	}

	return nil
}

type StagingForger struct {
	BaseForger
}

func NewStagingForger(p Project) *StagingForger {
	return &StagingForger{
		BaseForger: *NewBaseForger(p),
	}
}

func (f *StagingForger) Run(p Project) error {
	err := f.BaseForger.Run(p)
	if err != nil {
		return err
	}

	db, err := f.DBConfig()
	if err != nil {
		return err
	}
	maps.Copy(f.Vars, db)

	redis, err := f.RedisConfig()
	if err != nil {
		return err
	}
	maps.Copy(f.Vars, redis)

	mail, err := f.MailConfig()
	if err != nil {
		return err
	}
	maps.Copy(f.Vars, mail)

	return nil
}

func (f *BaseForger) DBConfig() (map[string]string, error) {
	host, port := os.Getenv("DB_HOST"), os.Getenv("DB_PORT")
	if host == "" || port == "" {
		return nil, errors.New("DB_HOST or DB_PORT not set in environment variables")
	}

	password, ok := f.Vars["DB_PASSWORD"]
	var err error
	if !ok {
		password, err = GenerateMySQLPassword()
		if err != nil {
			return nil, err
		}
	}

	return map[string]string{
		"DB_CONNECTION": "mysql",
		"DB_HOST":       host,
		"DB_PORT":       port,
		"DB_DATABASE":   f.Project.Slug,
		"DB_USERNAME":   fmt.Sprintf("%s_user", f.Project.Slug),
		"DB_PASSWORD":   password,
	}, nil
}

func (f *BaseForger) SQLConfig() string {
	config, _ := f.DBConfig()

	return fmt.Sprintf(
		`CREATE DATABASE %s CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '%s'@'%%' IDENTIFIED BY '%s';
GRANT ALL PRIVILEGES ON %s.* TO '%s'@'%%';
FLUSH PRIVILEGES;
`, config["DB_DATABASE"], config["DB_USERNAME"], config["DB_PASSWORD"], config["DB_DATABASE"], config["DB_USERNAME"])
}

func (f *StagingForger) MailConfig() (map[string]string, error) {
	vars := []string{
		"MAIL_ENCRYPTION", "MAIL_FROM_ADDRESS", "MAIL_FROM_NAME", "MAIL_HOST", "MAIL_MAILER", "MAIL_PASSWORD", "MAIL_PORT", "MAIL_USERNAME",
	}

	config := make(map[string]string, len(vars))
	for _, v := range vars {
		value, ok := os.LookupEnv(v)
		if !ok {
			return nil, fmt.Errorf("%s not set in environment variables", v)
		}
		config[v] = value
	}

	return config, nil
}

func GenerateMySQLPassword() (string, error) {
	bytes := make([]byte, 12)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	password := base64.StdEncoding.EncodeToString(bytes)

	password = strings.ReplaceAll(password, "+", "A")
	password = strings.ReplaceAll(password, "/", "B")
	password = strings.ReplaceAll(password, "=", "C")

	return password, nil
}

func (f *BaseForger) RedisConfig() (map[string]string, error) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		return nil, errors.New("REDIS_URL not set in environment variables")
	}

	return map[string]string{
		"REDIS_CLIENT": "predis",
		"REDIS_URL":    url,
		"REDIS_PREFIX": fmt.Sprintf("%s_database_", f.Project.Slug),
	}, nil
}

func (f *BaseForger) AppConfig() (map[string]string, error) {
	var name, appURL string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("APP_NAME").Placeholder("Laravel").Value(&name).Validate(f.ValidateRequired),
		),
		huh.NewGroup(
			huh.NewInput().Title("APP_URL").Placeholder("https://example.com").Value(&appURL).Validate(func(v string) error {
				_, err := url.ParseRequestURI(v)
				if err != nil {
					return errors.New("invalid URL format")
				}
				return nil
			}),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	u, err := url.ParseRequestURI(appURL)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"APP_NAME":               name,
		"VITE_APP_NAME":          "${APP_NAME}",
		"APP_URL":                appURL,
		"APP_DOMAIN":             u.Hostname(),
		"APP_ENV":                string(f.Project.Env),
		"APP_DEBUG":              "false",
		"APP_FAKER_LOCALE":       "en_US",
		"APP_FALLBACK_LOCALE":    "en",
		"APP_LOCALE":             "en",
		"APP_MAINTENANCE_DRIVER": "file",
		"BCRYPT_ROUNDS":          "12",
		"PHP_CLI_SERVER_WORKERS": "4",
	}, nil
}

func (f *BaseForger) AWSConfig() (map[string]string, error) {
	var key, secret, region, bucket, endpoint string
	region = "auto"

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("AWS_ACCESS_KEY_ID").Value(&key),
			huh.NewInput().Title("AWS_SECRET_ACCESS_KEY").Value(&secret).EchoMode(huh.EchoModePassword),
			huh.NewInput().Title("AWS_DEFAULT_REGION").Value(&region),
			huh.NewInput().Title("AWS_BUCKET").Value(&bucket),
			huh.NewInput().Title("AWS_ENDPOINT").Value(&endpoint),
		).Title("AWS Configuration"),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	return map[string]string{
		"AWS_ACCESS_KEY_ID":     key,
		"AWS_SECRET_ACCESS_KEY": secret,
		"AWS_DEFAULT_REGION":    region,
		"AWS_BUCKET":            bucket,
		"AWS_ENDPOINT":          endpoint,
	}, nil
}

func (f *BaseForger) FilesystemConfig() (map[string]string, error) {
	var disk string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Title("Filesystem Disk").Options(
				huh.NewOption("local", "local"),
				huh.NewOption("s3", "s3"),
			).Value(&disk),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	return map[string]string{
		"FILESYSTEM_DISK": disk,
	}, nil
}

func (f *BaseForger) CacheConfig() (map[string]string, error) {
	var driver string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Title("Cache Store").Options(
				huh.NewOption("Redis", "redis"),
				huh.NewOption("Database", "database"),
				huh.NewOption("File", "file"),
			).Value(&driver),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	return map[string]string{
		"CACHE_STORE":  driver,
		"CACHE_PREFIX": fmt.Sprintf("%s_cache_", f.Project.Slug),
	}, nil
}

func (f *BaseForger) SessionConfig() (map[string]string, error) {
	var driver string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Title("Session Driver").Options(
				huh.NewOption("Redis", "redis"),
				huh.NewOption("Database", "database"),
				huh.NewOption("File", "file"),
			).Value(&driver),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	return map[string]string{
		"SESSION_DRIVER":   driver,
		"SESSION_LIFETIME": "120",
		"SESSION_ENCRYPT":  "true",
		"SESSION_PATH":     "/",
		"SESSION_DOMAIN":   "${APP_DOMAIN}",
	}, nil
}

func (f *BaseForger) QueueConfig() (map[string]string, error) {
	var driver string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Title("Queue Driver").Options(
				huh.NewOption("Redis", "redis"),
				huh.NewOption("Database", "database"),
				huh.NewOption("Sync", "sync"),
			).Value(&driver),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	return map[string]string{
		"QUEUE_CONNECTION": driver,
	}, nil
}

func (f *BaseForger) BroadcastingConfig() (map[string]string, error) {
	var driver string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				TitleFunc(func() string {
					if f.Project.HasKey("REVERB_") {
						return "Broadcasting Driver (Reverb detected in env vars)"
					}
					return "Broadcasting Driver"
				}, nil).
				Options(
					huh.NewOption("Redis", "redis"),
					huh.NewOption("Reverb", "reverb"),
				).Value(&driver),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	return map[string]string{
		"BROADCAST_CONNECTION": driver,
	}, nil
}

func (f *BaseForger) LogConfig() (map[string]string, error) {
	logStack := "daily"
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Log Stack").Placeholder("e.g. daily or daily,mail").Value(&logStack).Suggestions([]string{"daily", "daily,mail"}).Validate(f.ValidateRequired),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	logLevel := "debug"
	if f.Project.Env == EnvProduction {
		logLevel = "info"
	}

	return map[string]string{
		"LOG_CHANNEL":              "stack",
		"LOG_STACK":                logStack,
		"LOG_DEPRECATIONS_CHANNEL": "null",
		"LOG_LEVEL":                logLevel,
	}, nil
}

func (f *BaseForger) AppKey() (map[string]string, error) {
	keyBytes := make([]byte, 32)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return nil, err
	}

	appKey := "base64:" + base64.StdEncoding.EncodeToString(keyBytes)

	return map[string]string{
		"APP_KEY": appKey,
	}, nil
}

func (f *BaseForger) HandleUnrecognizedVars() error {
	unrecognized, err := f.UnrecgonizedVars()
	if err != nil {
		return err
	}

	if len(unrecognized) == 0 {
		return nil
	}

	groupedKeys := make(map[string][]string)
	for k := range unrecognized {
		prefix := strings.Split(k, "_")[0]
		groupedKeys[prefix] = append(groupedKeys[prefix], k)
	}

	prefixes := make([]string, 0, len(groupedKeys))
	for p := range groupedKeys {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	values := make(map[string]*string)
	for k, v := range unrecognized {
		val := v.Value
		values[k] = &val
	}

	groups := make([]*huh.Group, 0)
	for _, prefix := range prefixes {
		keys := groupedKeys[prefix]
		sort.Strings(keys)

		fields := make([]huh.Field, 0, len(keys))
		for _, k := range keys {
			v := unrecognized[k]
			field := huh.NewInput().
				Title(fmt.Sprintf("%s (Source: %s)", k, v.Source)).
				Value(values[k])

			if strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "secret") || strings.Contains(strings.ToLower(k), "key") {
				field = field.EchoMode(huh.EchoModePassword)
			}

			fields = append(fields, field)
		}

		group := huh.NewGroup(fields...).Title(fmt.Sprintf("%s Configuration", strings.Title(strings.ToLower(prefix))))
		groups = append(groups, group)
	}

	form := huh.NewForm(groups...)
	if err := form.Run(); err != nil {
		return err
	}

	for k, v := range values {
		f.Vars[k] = *v
	}

	return nil
}

func (f *BaseForger) UnrecgonizedVars() (map[string]EnvValue, error) {
	typical, err := godotenv.Read("./.env.laravel.example")
	if err != nil {
		return nil, err
	}

	var unrecognized = make(map[string]EnvValue)
	for k, v := range f.Project.EnvVars {
		if _, ok := typical[k]; ok {
			continue
		}

		if k == "APP_DOMAIN" {
			continue
		}

		unrecognized[k] = v
	}

	return unrecognized, nil
}

type ProductionForger struct {
	BaseForger
}

func NewProductionForger(p Project) *ProductionForger {
	return &ProductionForger{
		BaseForger: *NewBaseForger(p),
	}
}

func (f *ProductionForger) Run(p Project) error {
	if err := f.BaseForger.Run(p); err != nil {
		return err
	}

	db, err := f.DBConfig()
	if err != nil {
		return err
	}
	maps.Copy(f.Vars, db)

	redis, err := f.RedisConfig()
	if err != nil {
		return err
	}
	maps.Copy(f.Vars, redis)

	mail, err := f.MailConfig()
	if err != nil {
		return err
	}
	maps.Copy(f.Vars, mail)

	return nil
}

func (f *ProductionForger) MailConfig() (map[string]string, error) {
	var mailer, host, port, username, password, encryption, fromAddress, fromName string
	mailer = "smtp"
	port = "587"
	encryption = "tls"

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("MAIL_MAILER").Value(&mailer),
			huh.NewInput().Title("MAIL_HOST").Value(&host),
			huh.NewInput().Title("MAIL_PORT").Value(&port),
			huh.NewInput().Title("MAIL_USERNAME").Value(&username),
			huh.NewInput().Title("MAIL_PASSWORD").Value(&password).EchoMode(huh.EchoModePassword),
			huh.NewInput().Title("MAIL_ENCRYPTION").Value(&encryption),
			huh.NewInput().Title("MAIL_FROM_ADDRESS").Value(&fromAddress),
			huh.NewInput().Title("MAIL_FROM_NAME").Value(&fromName),
		).Title("Mail Configuration"),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	return map[string]string{
		"MAIL_MAILER":       mailer,
		"MAIL_HOST":         host,
		"MAIL_PORT":         port,
		"MAIL_USERNAME":     username,
		"MAIL_PASSWORD":     password,
		"MAIL_ENCRYPTION":   encryption,
		"MAIL_FROM_ADDRESS": fromAddress,
		"MAIL_FROM_NAME":    fromName,
	}, nil
}
