package pkg

import "encoding/json"

// dropUnresolvedSPDX3Relationships removes relationship endpoints that point
// at elements defined in another SPDX document. tools-golang refuses to load
// a graph until every from/to IRI resolves, which drops otherwise scannable
// SBOMs such as the binary documents in spdx-examples.
func dropUnresolvedSPDX3Relationships(data []byte) []byte {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return data
	}
	graph, ok := doc["@graph"].([]any)
	if !ok {
		return data
	}

	local := spdx3LocalIDs(graph)
	rewritten := make([]any, 0, len(graph))
	changed := false
	for _, raw := range graph {
		element, ok := raw.(map[string]any)
		if !ok {
			rewritten = append(rewritten, raw)
			continue
		}
		next, keep, touched := filterSPDX3Relationship(element, local)
		if touched {
			changed = true
		}
		if keep {
			rewritten = append(rewritten, next)
		}
	}
	if scrubSPDX3Collections(rewritten) {
		changed = true
	}
	if !changed {
		return data
	}

	doc["@graph"] = rewritten
	out, err := json.Marshal(doc)
	if err != nil {
		return data
	}
	return out
}

func scrubSPDX3Collections(graph []any) bool {
	local := spdx3LocalIDs(graph)
	changed := false
	for _, raw := range graph {
		element, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"element", "rootElement"} {
			if scrubSPDX3IDList(element, key, local) {
				changed = true
			}
		}
	}
	return changed
}

func scrubSPDX3IDList(element map[string]any, key string, local map[string]struct{}) bool {
	value, ok := element[key]
	if !ok {
		return false
	}
	kept, changed := localSPDX3Refs(value, local)
	if !changed {
		return false
	}
	if len(kept) == 0 {
		delete(element, key)
		return true
	}
	element[key] = kept
	return true
}

func spdx3LocalIDs(graph []any) map[string]struct{} {
	ids := make(map[string]struct{})
	for _, raw := range graph {
		element, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"@id", "spdxId"} {
			if id, ok := element[key].(string); ok && id != "" {
				ids[id] = struct{}{}
			}
		}
	}
	return ids
}

func filterSPDX3Relationship(element map[string]any, local map[string]struct{}) (map[string]any, bool, bool) {
	_, hasFrom := element["from"]
	_, hasTo := element["to"]
	if !hasFrom && !hasTo {
		return element, true, false
	}

	from, fromChanged := localSPDX3Refs(element["from"], local)
	to, toChanged := localSPDX3Refs(element["to"], local)
	if len(from) == 0 || len(to) == 0 {
		return nil, false, true
	}

	if !fromChanged && !toChanged {
		return element, true, false
	}
	element["from"] = from[0]
	element["to"] = to
	return element, true, true
}

func localSPDX3Refs(value any, local map[string]struct{}) ([]string, bool) {
	refs := spdx3RefList(value)
	if len(refs) == 0 {
		return nil, false
	}
	kept := make([]string, 0, len(refs))
	for _, ref := range refs {
		if _, ok := local[ref]; ok {
			kept = append(kept, ref)
		}
	}
	return kept, len(kept) != len(refs)
}

func spdx3RefList(value any) []string {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	case []any:
		refs := make([]string, 0, len(typed))
		for _, item := range typed {
			if ref, ok := item.(string); ok && ref != "" {
				refs = append(refs, ref)
			}
		}
		return refs
	default:
		return nil
	}
}
