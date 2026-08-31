package dnf

import "testing"

func TestAdvisorySeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  AdvisorySeverity
	}{
		{input: "Critical", want: AdvisorySeverityCritical},
		{input: "IMPORTANT", want: AdvisorySeverityImportant},
		{input: "high", want: AdvisorySeverityImportant},
		{input: "Moderate", want: AdvisorySeverityModerate},
		{input: "medium", want: AdvisorySeverityModerate},
		{input: "Low", want: AdvisorySeverityLow},
		{input: "None", want: AdvisorySeverityUnknown},
		{input: "", want: AdvisorySeverityUnknown},
		{input: "vendor-new-level", want: AdvisorySeverityUnknown},
	}

	for _, test := range tests {
		if got := ParseAdvisorySeverity(test.input); got != test.want {
			t.Errorf("ParseAdvisorySeverity(%q) = %v, want %v", test.input, got, test.want)
		}
		if !test.want.Valid() {
			t.Errorf("defined severity %v is invalid", test.want)
		}
		if test.want.String() == "" {
			t.Errorf("defined severity %v has an empty spelling", test.want)
		}
	}
	if AdvisorySeverity(255).Valid() {
		t.Fatal("undefined severity is valid")
	}
}
