package config

import (
	"github.com/caarlos0/env"
)

type Config struct {
	Port            string `env:"PORT"`
	DBUrl           string `env:"DATABASE_URL"`
	DBName          string `env:"DATABASE_NAME"`
	SecretKey       string `env:"SECRET_KEY"`
	AWSAccessKey    string `env:"AWS_ACCESS_KEY"`
	AWSSecreteKey   string `env:"AWS_SECRETE_KEY"`
	AWSS3Region     string `env:"AWS_S3_REGION"`
	AWSS3Bucket     string `env:"AWS_S3_BUCKET"`
	AWSS3BucketName string `env:"AWS_S3_BUCKET_NAME"`
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
