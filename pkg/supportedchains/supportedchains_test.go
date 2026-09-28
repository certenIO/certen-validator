package supportedchains

import "testing"

// The supported chains are exactly Ethereum Sepolia, Base Sepolia and Arbitrum Sepolia.
func TestTheSupportedChainsAreTheThreeRunningCurrentContracts(t *testing.T) {
	want := map[int64]string{11155111: "ethereum-sepolia", 84532: "base-sepolia", 421614: "arbitrum-sepolia"}
	if len(All) != len(want) {
		t.Fatalf("%d supported chains, want %d", len(All), len(want))
	}
	for id, name := range want {
		c, ok := Lookup(id)
		if !ok || c.Name != name {
			t.Fatalf("chain %d: %+v, %v", id, c, ok)
		}
	}
	for _, retired := range []int64{1, 11155420, 80002, 97, 1287, 296, 0} {
		if IsSupported(retired) {
			t.Fatalf("chain %d is supported", retired)
		}
	}
	if Describe() != "ethereum-sepolia (11155111), base-sepolia (84532), arbitrum-sepolia (421614)" {
		t.Fatalf("describe: %s", Describe())
	}
}
