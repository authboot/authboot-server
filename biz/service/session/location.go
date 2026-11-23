package session

import (
	model "github.com/authboot/authboot-server/biz/model/session"
	"github.com/authboot/authboot-server/pkg/geoip"
)

// LocationProto keeps old sessions explicitly unknown without looking up today's data.
func LocationProto(l geoip.Location) *model.IPLocation {
	if l.Status == "" {
		l = geoip.Unknown("unknown")
	}
	return &model.IPLocation{CountryCode: l.CountryCode, Country: l.Country, Region: l.Region, City: l.City, Display: l.Display, Source: l.Source, Status: l.Status}
}
