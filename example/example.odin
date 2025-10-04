package example

import "core:strings"
import "core:time"

import slotman "../"
Error :: Maybe(string)

import "core:fmt"

print :: fmt.println
main :: proc() {
	slotman.register_asset_type(TextFile, text_file_drop)
	slotman.register_asset_type(TextStats, nil)
	slotman.register_asset_directory("./example/texts")
	slotman.register_loader(TextFile, []u8, text_file_from_bytes)
	slotman.register_loader(TextStats, []string, text_stats_from_paths)

	hello_text := slotman.load_from_path(TextFile, "hello.txt")
	moin_text := slotman.load_from_path(TextFile, "moin.txt")
	greetings_text := slotman.load_from_path(TextFile, "greetings.txt")
	text_stats := slotman.load_from_input(
		TextStats,
		[]string{"hello.txt", "greetings.txt", "moin.txt"},
	)

	// print("dependencies:")
	// for a, d in slotman.MANAGER.asset_meta {
	// 	print(a)
	// 	print("   dependencies:", d.dependencies[:])
	// 	print("   dependants:", d.dependants[:][:])
	// }

	for {
		time.sleep(time.Millisecond * 200)
		slotman.hot_reload()
		print("---------------------------------------------")
		print("hello_text: ", slotman.get(hello_text).content)
		print("moin_text: ", slotman.get(moin_text).content)
		print("greetings_text: ", slotman.get(greetings_text).content)
		print("text stats: ", slotman.get(text_stats))
	}

}


// The TextStats asset is derived from a bunch of other assets and reloaded whenever a dependency changes
TextStats :: struct {
	word_count:   int,
	avg_word_len: f32,
}
text_stats_from_paths :: proc(paths: []string) -> (res: TextStats, err: Error) {
	print("text_stats_from_paths", paths)
	word_count := 0
	word_len_total := 0
	for path in paths {
		file_handle := slotman.try_load_from_path(TextFile, path) or_return
		file := slotman.get(file_handle)
		for word in strings.split_multi(file.content, {" ", "\n"}) {
			word := strings.trim_space(word)
			if len(word) > 0 {
				word_len_total += len(word)
				word_count += 1
			}
		}
	}
	res = TextStats {
		word_count   = word_count,
		avg_word_len = 0 if word_count == 0 else f32(word_len_total) / f32(word_count),
	}
	return res, nil
}

// just represents a text file but lines that start with "import" import the content of other text files.
// The text file is hot reloaded whenever its file changes or any dependency changes
TextFile :: struct {
	content: string,
}
text_file_drop :: proc(this: ^TextFile) {
	delete(this.content)
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
			strings.write_string(&b, "\n")
			strings.write_string(&b, other_asset.content)
		} else {
			strings.write_string(&b, line)
		}
	}
	return TextFile{strings.to_string(b)}, nil
}
