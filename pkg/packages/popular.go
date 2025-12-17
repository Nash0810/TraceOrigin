package packages

// Popular package names by ecosystem
// TODO: Populate in Iteration 3
var popularPackages = map[string][]string{
	"pip": {
		"flask", "django", "requests", "numpy", "pandas",
		"tensorflow", "torch", "pytest", "black", "pylint",
	},
	"npm": {
		"express", "react", "vue", "angular", "lodash",
		"axios", "webpack", "babel", "typescript", "eslint",
	},
}

func GetPopularPackages(pm string) []string {
	if packages, ok := popularPackages[pm]; ok {
		return packages
	}
	return []string{}
}
