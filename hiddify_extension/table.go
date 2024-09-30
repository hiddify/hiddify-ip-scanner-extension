package hiddify_extension
import(
	"strings"

)
func (e *CleanIPExtension) addRow(values ...interface{}) {
	e.tblMutex.Lock()
	defer e.tblMutex.Unlock()
	e.resultTbl.AddRow(values...)
}

func (e *CleanIPExtension) tableString() string {
	e.tblMutex.Lock()
	defer e.tblMutex.Unlock()
	var sb strings.Builder
	e.resultTbl.WithWriter(&sb).Print()
	return sb.String()
}

func (e *CleanIPExtension) tableClean() {
	e.tblMutex.Lock()
	defer e.tblMutex.Unlock()
	e.resultTbl.SetRows([][]string{})
}