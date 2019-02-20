package analyse_log

import (
	"testing"

	"github.com/influxdata/telegraf/testutil"

	"github.com/stretchr/testify/assert"
)

func TestStartNoParsers(t *testing.T) {
	logparser := &AnalyseLogPlugin{
		FromBeginning: true,
		Files:         []string{"testdata/*.log"},
	}

	acc := testutil.Accumulator{}
	assert.Error(t, logparser.Start(&acc))
}

