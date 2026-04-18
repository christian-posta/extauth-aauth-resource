package structfields

import (
	"testing"
)

func TestParseDictionary(t *testing.T) {
	input := `en="Applepie", da=*wibble`
	dict, err := ParseDictionary(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(dict) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(dict))
	}

	if dict[0].Name != "en" {
		t.Errorf("expected 'en', got %v", dict[0].Name)
	}
	item0 := dict[0].Value.(Item)
	if item0.Value.(string) != "Applepie" {
		t.Errorf("expected Applepie, got %v", item0.Value)
	}

	if dict[1].Name != "da" {
		t.Errorf("expected 'da', got %v", dict[1].Name)
	}
	item1 := dict[1].Value.(Item)
	if item1.Value.(Token) != "*wibble" {
		t.Errorf("expected *wibble, got %v", item1.Value)
	}
}

func TestSerializeDictionary(t *testing.T) {
	dict := Dictionary{
		{Name: "en", Value: Item{Value: "Applepie"}},
		{Name: "da", Value: Item{Value: Token("*wibble")}},
	}
	s, err := SerializeDictionary(dict)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := `en="Applepie", da=*wibble`
	if s != expected {
		t.Errorf("expected %q, got %q", expected, s)
	}
}

func TestParseItemWithParams(t *testing.T) {
	input := `?1;a=1;b="two"`
	item, err := ParseItem(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if item.Value != true {
		t.Errorf("expected true, got %v", item.Value)
	}
	if len(item.Params) != 2 {
		t.Fatalf("expected 2 params")
	}
	if item.Params[0].Name != "a" || item.Params[0].Value.(int64) != 1 {
		t.Errorf("param a bad: %v", item.Params[0])
	}
	if item.Params[1].Name != "b" || item.Params[1].Value.(string) != "two" {
		t.Errorf("param b bad: %v", item.Params[1])
	}
}

func TestInnerList(t *testing.T) {
	input := `("foo" "bar");baz`
	list, err := ParseList(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 element")
	}
	inner := list[0].(InnerList)
	if len(inner.Items) != 2 {
		t.Fatalf("expected 2 inner items")
	}
	if inner.Items[0].Value.(string) != "foo" {
		t.Errorf("inner item 0 bad")
	}
	if len(inner.Params) != 1 || inner.Params[0].Name != "baz" || inner.Params[0].Value != true {
		t.Errorf("inner list param bad")
	}
}
