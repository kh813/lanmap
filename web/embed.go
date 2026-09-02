package web

import (
	"embed"
)

//go:embed static/* template/* template/partials/*
var WebFS embed.FS
