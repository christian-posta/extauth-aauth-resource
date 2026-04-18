package structfields

// Token represents an RFC 8941 Token.
type Token string

// ListEntry is either an Item or an InnerList.
type ListEntry interface {
	IsListEntry()
}

// Item represents an RFC 8941 Item.
// Value can be: int64, float64, string, Token, []byte, bool.
type Item struct {
	Value  interface{}
	Params Params
}

func (Item) IsListEntry() {}

// InnerList represents an RFC 8941 Inner List.
type InnerList struct {
	Items  []Item
	Params Params
}

func (InnerList) IsListEntry() {}

// Param represents a parameter in a Params list.
type Param struct {
	Name  string
	Value interface{} // int64, float64, string, Token, []byte, bool
}

// Params is a list of parameters, preserving order.
type Params []Param

func (p Params) Get(name string) (interface{}, bool) {
	for _, param := range p {
		if param.Name == name {
			return param.Value, true
		}
	}
	return nil, false
}

// DictMember represents a member of a Dictionary.
type DictMember struct {
	Name  string
	Value ListEntry
}

// Dictionary is an ordered map of names to ListEntries.
type Dictionary []DictMember

func (d Dictionary) Get(name string) (ListEntry, bool) {
	for _, m := range d {
		if m.Name == name {
			return m.Value, true
		}
	}
	return nil, false
}

// List represents an RFC 8941 List.
type List []ListEntry
