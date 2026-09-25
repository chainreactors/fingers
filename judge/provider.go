package judge

import "context"

// Provider answers typed questions about a state. It is how a model plugs in:
// TypeSafe Jev (package judge/jev), an LLM, a local classifier or a
// cross-encoder reranker. A provider only transports questions and answers;
// caching, request merging, thresholds and every decision stay in Judge and
// the capabilities, so they behave the same whichever provider answers.
type Provider interface {
	// ID names the provider and model version. It scopes cached answers:
	// change it whenever the same question may be answered differently.
	ID() string
	// Judge answers every question in one call, keyed as questions are.
	// A missing answer is treated as no answer, not as an error.
	Judge(ctx context.Context, state interface{}, questions map[string]Question) (map[string]Answer, error)
}

// Calibrated is implemented by providers whose answers were measured on a
// labelled set (see cmd/judgeeval): New then uses their thresholds.
type Calibrated interface {
	// Calibration returns the Yes probability that counts as "yes" and the
	// confidence at which a picked version is adopted.
	Calibration() (threshold, versionConfidence float64)
}

// QuestionType is the answer shape a question asks for.
type QuestionType string

const (
	TypeBinary QuestionType = "binary" // Answer.Yes: probability of "yes"; independent per question
	TypeChoice QuestionType = "choice" // Answer.Choice: one of Options, with Confidence: a rerank over options
	TypeScore  QuestionType = "score"  // Answer.Score: position on Levels, from 0 to 1
)

// Question is provider-neutral: plain instructions plus the options or levels.
type Question struct {
	Type         QuestionType `json:"type"`
	Instructions string       `json:"instructions"`
	// Options: for TypeChoice, option -> description ("" for none); for
	// TypeBinary, optional descriptions of "true" and "false".
	Options map[string]string `json:"options,omitempty"`
	Levels  []string          `json:"levels,omitempty"` // TypeScore: 2..10 ordered level descriptions
}

func Binary(instructions string) Question {
	return Question{Type: TypeBinary, Instructions: instructions}
}

// BinaryWith describes what "yes" and "no" mean, which sharpens the answer.
func BinaryWith(instructions, yes, no string) Question {
	return Question{Type: TypeBinary, Instructions: instructions, Options: map[string]string{"true": yes, "false": no}}
}

func Choice(instructions string, options map[string]string) Question {
	return Question{Type: TypeChoice, Instructions: instructions, Options: options}
}

func Score(instructions string, levels []string) Question {
	return Question{Type: TypeScore, Instructions: instructions, Levels: levels}
}

// Answer is one answer; only the fields of the question's type are set.
type Answer struct {
	Yes           float64            `json:"yes,omitempty"`
	Choice        string             `json:"choice,omitempty"`
	Score         float64            `json:"score,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"` // choice: per option
	Confidence    float64            `json:"confidence,omitempty"`
}
