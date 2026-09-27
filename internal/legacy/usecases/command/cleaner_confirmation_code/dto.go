package cleanerconfirmationcode

type Request struct {
	BatchSize  int
	Iterations int
	Minutes    int
}

type Response struct {
	Total int64
}
