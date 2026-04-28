// Package pihole holds the Pi-hole v6 REST API client used by the DNS
// collector group. The client handles app-password → SID exchange, session
// reuse, and reauth on 401.
//
// Implementation lands in a follow-up PR. This package exists at scaffold
// time so the rest of the layout has a stable import home.
package pihole
