package passive

import (
	"strings"

	"golang.org/x/exp/maps"

	"github.com/YouChenJun/subfinder-plus/pkg/subscraping"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/alienvault"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/anubis"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/bevigil"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/binaryedge"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/bufferover"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/builtwith"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/c99"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/censys"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/certspotter"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/chaos"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/chinaz"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/commoncrawl"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/crtsh"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/digitalyama"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/digitorus"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/dnsdb"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/dnsdumpster"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/dnsrepo"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/facebook"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/fofa"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/fullhunt"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/github"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/hackertarget"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/hudsonrock"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/hunter"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/intelx"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/leakix"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/netlas"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/quake"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/rapiddns"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/redhuntlabs"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/robtex"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/securitytrails"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/shodan"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/sitedossier"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/threatbook"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/threatcrowd"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/virustotal"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/waybackarchive"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/whoisxmlapi"
	"github.com/YouChenJun/subfinder-plus/pkg/subscraping/sources/zoomeyeapi"
	"github.com/projectdiscovery/gologger"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

var AllSources = [...]subscraping.Source{
	&alienvault.Source{},
	&anubis.Source{},
	&bevigil.Source{},
	&binaryedge.Source{},
	&bufferover.Source{},
	&c99.Source{},
	&censys.Source{},
	&certspotter.Source{},
	&chaos.Source{},
	&chinaz.Source{},
	&commoncrawl.Source{},
	&crtsh.Source{},
	&digitorus.Source{},
	&dnsdb.Source{},
	&dnsdumpster.Source{},
	&dnsrepo.Source{},
	&fofa.Source{},
	&fullhunt.Source{},
	&github.Source{},
	&hackertarget.Source{},
	&hunter.Source{},
	&intelx.Source{},
	&netlas.Source{},
	&leakix.Source{},
	&quake.Source{},
	&rapiddns.Source{},
	&redhuntlabs.Source{},
	// &riddler.Source{}, // failing due to cloudfront protection
	&robtex.Source{},
	&securitytrails.Source{},
	&shodan.Source{},
	&sitedossier.Source{},
	&threatbook.Source{},
	&threatcrowd.Source{},
	&virustotal.Source{},
	&waybackarchive.Source{},
	&whoisxmlapi.Source{},
	&zoomeyeapi.Source{},
	&facebook.Source{},
	// &threatminer.Source{}, // failing  api
	// &reconcloud.Source{}, // failing due to cloudflare bot protection
	&builtwith.Source{},
	&hudsonrock.Source{},
	&digitalyama.Source{},
}

var sourceWarnings = mapsutil.NewSyncLockMap[string, string](
	mapsutil.WithMap(mapsutil.Map[string, string]{}))

var NameSourceMap = make(map[string]subscraping.Source, len(AllSources))

func init() {
	for _, currentSource := range AllSources {
		NameSourceMap[strings.ToLower(currentSource.Name())] = currentSource
	}
}

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources []subscraping.Source
}

// New creates a new agent for passive subdomain discovery
func New(sourceNames, excludedSourceNames []string, useAllSources, useSourcesSupportingRecurse bool) *Agent {
	sources := make(map[string]subscraping.Source, len(AllSources))

	if useAllSources {
		maps.Copy(sources, NameSourceMap)
	} else {
		if len(sourceNames) > 0 {
			for _, source := range sourceNames {
				if NameSourceMap[source] == nil {
					gologger.Warning().Msgf("There is no source with the name: %s", source)
				} else {
					sources[source] = NameSourceMap[source]
				}
			}
		} else {
			for _, currentSource := range AllSources {
				if currentSource.IsDefault() {
					sources[currentSource.Name()] = currentSource
				}
			}
		}
	}

	if len(excludedSourceNames) > 0 {
		for _, sourceName := range excludedSourceNames {
			delete(sources, sourceName)
		}
	}

	if useSourcesSupportingRecurse {
		for sourceName, source := range sources {
			if !source.HasRecursiveSupport() {
				delete(sources, sourceName)
			}
		}
	}

	if len(sources) == 0 {
		gologger.Fatal().Msg("No sources selected for this search")
	}

	gologger.Debug().Msgf("Selected source(s) for this search: %s", strings.Join(maps.Keys(sources), ", "))

	for _, currentSource := range sources {
		if warning, ok := sourceWarnings.Get(strings.ToLower(currentSource.Name())); ok {
			gologger.Warning().Msg(warning)
		}
	}

	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: maps.Values(sources)}

	return agent
}
