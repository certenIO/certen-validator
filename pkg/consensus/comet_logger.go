package consensus

import (
	"io"

	cmtlog "github.com/cometbft/cometbft/libs/log"

	"github.com/certen/independant-validator/pkg/accumulate"
)

// cometLogger is CometBFT's logger at the validator's LOG_LEVEL: "info" (the default) prints CometBFT's info and error
// lines, "debug" its debug lines too; any other value is refused (accumulate.LogLevelFromEnv).
//
// RB5-F47: the logger was built without a level, so every node printed CometBFT's debug lines - p2p packet reads alone
// were half of each container's log - while configured LOG_LEVEL=info. The json-file retention (50 MB x 3) then held
// about six minutes: the record of a member's refusal on 2026-10-02 23:46 was gone by 23:54.
func cometLogger(w io.Writer) (cmtlog.Logger, error) {
	lvl, err := accumulate.LogLevelFromEnv()
	if err != nil {
		return nil, err
	}
	allow := cmtlog.AllowInfo()
	if lvl == "debug" {
		allow = cmtlog.AllowDebug()
	}
	return cmtlog.NewFilter(cmtlog.NewTMLogger(cmtlog.NewSyncWriter(w)).With("module", "cometbft"), allow), nil
}
