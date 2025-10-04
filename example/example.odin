package example

import "core:strings"

import slotman "../"
Error :: Maybe(string)

import "core:fmt"

print :: fmt.println
main :: proc() {

	slotman.register_asset_directory("./example/texts")
	slotman.register_loader(TextFile, []u8, text_file_from_bytes)
	print("Hello")
}


TextFile :: struct {
	content: string,
}
text_file_from_bytes :: proc(bytes: []u8) -> (file: TextFile, err: Error) {
	s := string(bytes)

	b: strings.Builder
	defer if err != nil {
		strings.builder_destroy(&b)
	}
	for line in strings.split_lines(s) {
		if strings.starts_with(line, "import ") {
			rel_file_path, _ := strings.substring(line, len("import "), len(line))
			rel_file_path = strings.trim_space(rel_file_path)
			other := slotman.try_load_from_path(TextFile, rel_file_path) or_return
			other_asset := slotman.get(other)
			strings.write_string(&b, other_asset.content)
		} else {
			strings.write_string(&b, line)
		}
	}
	return TextFile{strings.to_string(b)}, nil
}
