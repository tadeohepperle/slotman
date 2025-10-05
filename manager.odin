package slotman

import "base:runtime"
import "core:container/queue"
import "core:hash"
import "core:mem"
import "core:os"
import "core:path/filepath"
import "core:slice"
import "core:strings"
import "core:time"

import "base:intrinsics"
import "core:fmt"
Error :: Maybe(string)

// /////////////////////////////////////////////////////////////////////////////
// SECTION: Public interface
// /////////////////////////////////////////////////////////////////////////////

get_ref :: proc(handle: Handle($T)) -> ^T {
	return slotmap_get_ref(get_slotmap_ref(T), handle)
}

get :: proc(handle: Handle($T)) -> T {
	return slotmap_get(get_slotmap(T), handle)
}

insert :: proc(data: $T) -> Handle(T) {
	slotmap := get_slotmap_ref(T)
	return slotmap_insert(slotmap, data)
}

// returns true if this was the last reference
remove :: proc(handle: Handle($T)) -> bool {
	slotmap := get_slotmap_ref(T)
	ref_count := slotmap_get_ref_count(slotmap^, handle)
	// remove from dependencies, this can fail if other assets still depend on it! In that case the asset is not removed!
	if ref_count == 1 {
		asset := AssetTypeAndIdx{T, handle.idx}
		if !_try_remove_asset_from_graphs(asset) {
			fmt.eprintfln(
				"Warning: cannot remove assset {} because other assets still depend on it",
				asset,
			)
			return false
		}
	}
	return slotmap_remove(slotmap, handle)
}
// returns false if asset cannot be removed because others still depend on it
_try_remove_asset_from_graphs :: proc(asset: AssetTypeAndIdx) -> (ok: bool) {
	if asset in MANAGER.asset_metadata {
		deps: AssetMetadata
		_, deps = delete_key(&MANAGER.asset_metadata, asset)
		if len(deps.dependants) > 0 {
			return false
		}

		// remove dependencies to other assets:
		for dep in deps.dependencies {
			dep_entry := _get_asset_deps(dep)
			for d, idx in dep_entry.dependants {
				if d == asset {
					unordered_remove(&dep_entry.dependants, idx)
					break
				}
			}
		}

		// remove dependencies to files:
		for path in deps.file_dependencies {
			meta := _get_file_metadata(path)
			for d, idx in meta.dependants {
				if d == asset {
					unordered_remove(&meta.dependants, idx)
					break
				}
			}
		}

		// remove input data:
		input_key := AssetAndInputType{asset.asset_ty, deps.input_ty}
		input_cache, has_input := &MANAGER.input_caches[input_key]
		assert(has_input)
		for e, idx in input_cache.elements {
			if e.asset_idx == asset.idx {
				mem.free(e.boxed_input)
				unordered_remove(&input_cache.elements, idx)
				break
			}
		}
	}
	return true
}

clone_handle :: proc(handle: Handle($T)) {
	slotmap_clone_handle(get_slotmap_ref(T), handle)
}

try_load_full_path :: proc(partial_path: string) -> (full_path: string, err: Error) {
	partial_path := PartialPath(partial_path)
	_add_file_dependency(partial_path)
	meta := _get_or_insert_file_metadata(partial_path) or_return
	return meta.full_path, nil
}

try_load_bytes :: proc(partial_path: string) -> (file_bytes: []u8, err: Error) {
	partial_path := PartialPath(partial_path)
	_add_file_dependency(partial_path)
	meta := _get_or_insert_file_metadata(PartialPath(partial_path)) or_return
	if file_bytes, ok := meta.file_bytes.([]u8); ok {
		return file_bytes, nil
	}
	bytes, f_err := os.read_entire_file_from_filename_or_err(meta.full_path)
	if f_err != nil {
		return {}, fmt.tprintf("could not read file at {}: {}", meta.full_path, f_err)
	}
	meta.file_bytes = bytes
	return bytes, nil
}

_add_file_dependency :: proc(partial_path: PartialPath) {
	if len(MANAGER.load_scopes) > 0 {
		last := &MANAGER.load_scopes[len(MANAGER.load_scopes) - 1]
		if !slice.any_of(last.file_dependencies[:], partial_path) {
			append(&last.file_dependencies, partial_path)
		}
	}
}

load_from_path :: proc($T: typeid, path: string) -> Handle(T) {
	res, err := try_load_from_path(T, path)
	asset_ty: typeid = T
	if err, has_err := err.(string); has_err {
		fmt.panicf("Could not load asset {} from path {}: {}", asset_ty, path, err)
	}
	return res
}
try_load_from_path :: proc($T: typeid, partial_path: string) -> (handle: Handle(T), err: Error) {
	return try_load(T, partial_path)
}

load :: proc($T: typeid, input: any) -> Handle(T) {
	asset_ty: typeid = T
	handle, err := try_load(T, input)
	if err, has_err := err.(string); has_err {
		fmt.panicf("Could not load asset {} from input {}: {}", asset_ty, input, err)
	}
	return handle
}

try_load :: proc($T: typeid, input: any) -> (handle: Handle(T), err: Error) {

	_push_load_scope()
	defer if err != nil do _pop_load_scope(nil, false)

	asset_ty: typeid = T
	input_ty: typeid = input.id
	input_data: rawptr = input.data

	defer print("return try load:", asset_ty, handle)

	pair := AssetAndInputType{asset_ty, input_ty}
	input_cache, has_input_cache := &MANAGER.input_caches[pair]
	if !has_input_cache {
		return {}, fmt.tprintf("no input loader ({} -> {}) registered!", input_ty, asset_ty)
	}

	if input_cache.input_eq_fn != nil {
		// check cache if there is already an asset with the same input
		for elem in input_cache.elements {
			if input_cache.input_eq_fn(elem.boxed_input, input_data) {
				// found the right asset!
				print(asset_ty, "input: ", input, "found: ", get(Handle(T){elem.asset_idx}))
				handle = Handle(T){elem.asset_idx}
				clone_handle(handle)
				_pop_load_scope(AssetTypeAndIdx{asset_ty, handle.idx}, false)
				return handle, nil
			}
		}
	}
	print(asset_ty, "input: ", input, "no early return")

	// determine which loader to use: always loader for this input type except for string (partial path) as input bytes loader can be used
	use_bytes_loader: bool = false
	loader: Loader
	set_loader: if _loader, ok := input_cache.loader.(Loader); ok {
		loader = _loader
	} else {
		b_pair := AssetAndInputType{asset_ty, []u8}
		if b_cache, ok := MANAGER.input_caches[b_pair]; ok && input_ty == string {
			if b_loader, ok := b_cache.loader.(Loader); ok {
				loader = b_loader
				use_bytes_loader = true
				break set_loader
			}
		}
		return {}, fmt.tprintf("no input loader ({} -> {}) registered!", input_ty, asset_ty)
	}

	// special treatment of string input: strings are treated as partial paths.
	// for string inputs we try to resolve the full path and then hand that over to the loader function.
	// or if only a bytes loader is registered, we load the bytes from that function,
	// cache them in a file cache and hand them to the bytes loader function.
	res: T
	_load_input_to_out(input_ty, input_data, loader, use_bytes_loader, &res) or_return

	handle = slotmap_insert(get_slotmap_ref(T), res)
	asset := AssetTypeAndIdx{T, handle.idx}

	// insert input into input cache
	input_data_boxed, alloc_err := mem.alloc(input_cache.input_size, input_cache.input_align)
	assert(alloc_err == .None)
	mem.copy_non_overlapping(input_data_boxed, input_data, input_cache.input_size)
	append(&input_cache.elements, InputCacheElement{handle.idx, input_data_boxed})

	// pop the load scope, this sets the dependencies of this asset
	_insert_asset_metadata(asset, input_ty, input_data_boxed)
	_pop_load_scope(asset, true)

	return handle, nil
}

_load_input_to_out :: proc(
	input_ty: typeid,
	input_data: rawptr,
	loader: Loader,
	use_bytes_loader: bool,
	out: rawptr,
) -> (
	err: Error,
) {
	// special treatment of string input: strings are treated as partial paths.
	// for string inputs we try to resolve the full path and then hand that over to the loader function.
	// or if only a bytes loader is registered, we load the bytes from that function,
	// cache them in a file cache and hand them to the bytes loader function.
	if input_ty == string {
		partial_path: string = (cast(^string)input_data)^
		if use_bytes_loader {
			// pass bytes to loader:
			bytes_view: []u8 = try_load_bytes(partial_path) or_return
			loader_load(loader, &bytes_view, out)
		} else {
			// get full path and pass to loader:
			full_path_view: string = try_load_full_path(partial_path) or_return
			loader_load(loader, &full_path_view, out) or_return
		}
	} else {
		loader_load(loader, input_data, out) or_return
	}
	return nil
}


_get_or_insert_file_metadata :: proc(
	partial_path: PartialPath,
) -> (
	meta: ^FileMetadata,
	err: Error,
) {
	if partial_path not_in MANAGER.file_cache {
		stat := _find_full_path(partial_path) or_return
		owned_partial_path := PartialPath(strings.clone(string(partial_path)))
		MANAGER.file_cache[owned_partial_path] = FileMetadata {
			full_path     = stat.fullpath,
			last_mod_time = stat.modification_time,
			file_bytes    = nil,
			dependants    = make([dynamic]AssetTypeAndIdx),
		}
	}
	return &MANAGER.file_cache[partial_path], nil
}


_get_file_metadata :: #force_inline proc(partial_path: PartialPath) -> ^FileMetadata {
	meta, ok := &MANAGER.file_cache[partial_path]
	if !ok {
		fmt.panicf("should have file metadata for {}", partial_path)
	}
	return meta
}

get_slotmap_ref :: proc($T: typeid) -> ^Slotmap(T) {
	asset_ty: typeid = T
	slotmap: ^SlotmapPunned =
		&MANAGER.storage[asset_ty] or_else fmt.panicf("asset type {} not registered!", asset_ty)
	return cast(^Slotmap(T))slotmap
}

get_slotmap :: proc($T: typeid) -> Slotmap(T) {
	return get_slotmap_ref(T)^
}

// returns in tmp!
_find_full_path :: proc(partial_path: PartialPath) -> (stat: os.File_Info, err: Error) {
	for dir in MANAGER.asset_directories {
		full_path := fmt.tprintf("{}{}", dir, partial_path)
		stat := os.stat(full_path, context.temp_allocator) or_continue
		return stat, nil
	}
	return {}, fmt.tprintf("full path for partial_path {} not found", partial_path)
}

// drop is nullable!
register_type :: proc($T: typeid, drop: proc(this: ^T) = nil) {
	assert(!MANAGER.frozen, "Cannot register type after freezing manager!")
	asset_ty: typeid = T
	if asset_ty in MANAGER.storage {
		fmt.eprintfln("Type {} already registered!", asset_ty)
		return
	}
	MANAGER.storage[asset_ty] = transmute(SlotmapPunned)slotmap_create(T, drop)
}

punned_load_fn :: #type proc(
	original_load_fn: rawptr,
	input: rawptr,
	output: rawptr,
) -> (
	err: Error
)
Loader :: struct {
	original_load_fn: rawptr,
	punned_load_fn:   punned_load_fn,
}
loader_load :: proc(punned: Loader, input: rawptr, output: rawptr) -> (err: Error) {
	return punned.punned_load_fn(punned.original_load_fn, input, output)
}

register_path_loader :: proc(
	$T: typeid,
	from_path: proc(path: string) -> (this: T, error: Error),
) {
	register_loader(T, string, from_path)
}

register_bytes_loader :: proc(
	$T: typeid,
	from_bytes: proc(input: []u8) -> (this: T, error: Error),
) {
	// bytes_eq_fn :: proc "contextless" (a: ^[]u8, b: ^[]u8) -> bool {
	// 	a := a^
	// 	b := b^
	// 	if len(a) != len(b) {
	// 		return false
	// 	}
	// 	return runtime.memory_compare(raw_data(a), raw_data(b), len(a)) == 0
	// }
	register_loader(T, []u8, from_bytes)
}

punned_eq_proc :: #type proc "contextless" (_: rawptr, _: rawptr) -> bool
type_eq_proc :: proc($T: typeid) -> punned_eq_proc {
	when intrinsics.type_is_comparable(T) {
		return intrinsics.type_equal_proc(T)
	} else {
		return nil
	}
}

register_loader :: proc(
	$T: typeid,
	$I: typeid,
	load_fn: proc(input: I) -> (this: T, error: Error),
	// custom_eq_fn: proc "contextless" (a: ^I, b: ^I) -> bool,
) {
	asset_ty: typeid = T
	input_ty: typeid = I
	input_eq_fn := type_eq_proc(I)
	// input_eq_fn := cast(punned_eq_proc)custom_eq_fn if custom_eq_fn != nil else type_eq_proc(I)
	// if input_ty == string do assert(custom_eq_fn == nil)

	if asset_ty not_in MANAGER.storage {
		fmt.panicf(
			"Cannot register loader for asset type {} because there is no map for it yet!",
			asset_ty,
		)
	}

	assert(asset_ty in MANAGER.storage, "Cannot register loader")
	assert(!MANAGER.frozen, "Cannot register asset loader after freezing manager!")

	pair := AssetAndInputType{asset_ty, input_ty}
	if c, ok := MANAGER.input_caches[pair]; ok && c.loader != nil {
		fmt.eprintfln(
			"Asset type {} already has loader for config type {} registered!",
			asset_ty,
			input_ty,
		)
		return
	}

	// to make the proc type signature compatible
	punned_load_fn := proc(
		original_load_fn: rawptr,
		input: rawptr,
		output: rawptr,
	) -> (
		error: Error,
	) {
		input: ^I = cast(^I)input
		output: ^T = cast(^T)output
		original_load_fn := cast(proc(input: I) -> (this: T, error: Error))original_load_fn

		local: T = original_load_fn(input^) or_return
		output^ = local
		return nil
	}

	input_cache := InputCache {
		asset_ty = asset_ty,
		input_ty = input_ty,
		input_size = size_of(I),
		input_align = align_of(I),
		loader = Loader{original_load_fn = cast(rawptr)load_fn, punned_load_fn = punned_load_fn},
		input_eq_fn = input_eq_fn,
		elements = make([dynamic]InputCacheElement),
	}
	MANAGER.input_caches[pair] = input_cache

	if I == []u8 {
		// for byte loaders, also register an input cache for partial paths
		// there is special logic that tries to find a byte loader if for the string type as input the loader == nil
		s_pair := AssetAndInputType{asset_ty, string}
		if s_pair not_in MANAGER.input_caches {
			s_input_cache := InputCache {
				asset_ty    = asset_ty,
				input_ty    = string,
				input_size  = size_of(string),
				input_align = align_of(string),
				loader      = nil,
				input_eq_fn = intrinsics.type_equal_proc(string),
				elements    = make([dynamic]InputCacheElement),
			}
			MANAGER.input_caches[s_pair] = s_input_cache
		}
	}
}

register_asset_directory :: proc(path: string) {
	assert(!MANAGER.frozen, "Cannot register asset directories after freezing manager!")
	owned_path: string
	if !strings.ends_with(path, filepath.SEPARATOR_STRING) {
		owned_path = fmt.aprintf("{}{}", path, filepath.SEPARATOR_STRING)
	} else {
		owned_path = strings.clone(path)
	}
	append(&MANAGER.asset_directories, owned_path)
}

// call after all types and loaders are registered
freeze_types_and_loaders :: proc() {
	MANAGER.frozen = true
}

loader_proc_punned :: #type proc(input: rawptr, out: rawptr) -> (error: Error)


// /////////////////////////////////////////////////////////////////////////////
// SECTION: Internals
// /////////////////////////////////////////////////////////////////////////////


AssetAndInputType :: struct {
	asset_ty: typeid,
	input_ty: typeid,
}

AssetTypeAndIdx :: struct {
	asset_ty: typeid,
	idx:      u32,
}

// TODO: use a perfect hash function to replace map[typeid]SlotmapPunned with []SlotmapPunned

// @(private)
MANAGER: Manager
Manager :: struct {
	frozen:            bool,
	asset_directories: [dynamic]string,
	input_caches:      map[AssetAndInputType]InputCache,
	file_cache:        map[PartialPath]FileMetadata,
	storage:           map[typeid]SlotmapPunned,
	// maps partial path to full path, bytes and all assets that were loaded from it
	load_scopes:       [dynamic]LoadScope,
	// not all assets are in here, only those with inputs and dependencies
	asset_metadata:    map[AssetTypeAndIdx]AssetMetadata,
}

InputCache :: struct {
	asset_ty:    typeid,
	input_ty:    typeid,
	input_size:  int,
	input_align: int,
	loader:      Maybe(Loader), // can only be nil for the input type string! in that case if nil, the bytes loader is looked up and used
	input_eq_fn: proc "contextless" (a: rawptr, b: rawptr) -> bool,
	elements:    [dynamic]InputCacheElement,
}
InputCacheElement :: struct {
	asset_idx:   u32,
	boxed_input: rawptr,
}


@(private)
_asset_manager_drop :: proc(manager: ^Manager) {
	for _, input_cache in manager.input_caches {
		delete(input_cache.elements)
	}
	delete(manager.input_caches)
	manager.input_caches = {}

	for ty, &slotmap in manager.storage {
		slotmap_punned_drop(&slotmap)
	}
	delete(manager.storage)
	manager.storage = {}

	for path in manager.asset_directories {
		delete(path)
	}
	delete(manager.asset_directories)
	manager.asset_directories = {}

	for partial_path, meta in manager.file_cache {
		delete(string(partial_path))
		delete(meta.full_path)
		if file_bytes, ok := meta.file_bytes.([]u8); ok {
			delete(file_bytes)
		}
		delete(meta.dependants)
	}
	manager.file_cache = {}

	for l in manager.load_scopes {
		delete(l.dependencies)
	}
	delete(manager.load_scopes)
	manager.load_scopes = {}

	for asset, meta in manager.asset_metadata {
		delete(meta.dependants)
		delete(meta.dependants)
		delete(meta.file_dependencies)
	}
	delete(manager.asset_metadata)
	manager.asset_metadata = {}
}

AssetMetadata :: struct {
	input_ty:          typeid,
	input_data_view:   rawptr, // also stored in input_cache! same allocation!
	file_dependencies: [dynamic]PartialPath,
	dependencies:      [dynamic]AssetTypeAndIdx,
	dependants:        [dynamic]AssetTypeAndIdx,
}

LoadScope :: struct {
	file_dependencies: [dynamic]PartialPath, // paths here are views into paths allocated as map keys in MANAGER
	dependencies:      [dynamic]AssetTypeAndIdx,
}

_push_load_scope :: proc() {
	load_scope := LoadScope {
		dependencies = make([dynamic]AssetTypeAndIdx),
	}
	append(&MANAGER.load_scopes, load_scope)
}

_pop_load_scope :: proc(asset: Maybe(AssetTypeAndIdx), set_dependencies: bool) {
	assert(len(MANAGER.load_scopes) > 0)
	load_scope := pop(&MANAGER.load_scopes)

	// print("--- called _pop_load_scope for", asset, load_scope.dependencies[:])
	defer delete(load_scope.dependencies)
	if asset, ok := asset.(AssetTypeAndIdx); ok {
		if set_dependencies {
			_set_dependencies(asset, load_scope.file_dependencies[:], load_scope.dependencies[:])
		}
		// add this asset as dependency to parent scope where this function was called
		if len(MANAGER.load_scopes) > 0 {
			parent_scope := &MANAGER.load_scopes[len(MANAGER.load_scopes) - 1]
			if !slice.any_of(parent_scope.dependencies[:], asset) {
				append(&parent_scope.dependencies, asset)
			}
		}
	}

}

_get_asset_deps :: proc(asset: AssetTypeAndIdx) -> ^AssetMetadata {
	deps, ok := &MANAGER.asset_metadata[asset]
	assert(ok, "should have asset in dependency graph")
	return deps
}

_insert_asset_metadata :: proc(asset: AssetTypeAndIdx, input_ty: typeid, input_data_view: rawptr) {
	assert(asset not_in MANAGER.asset_metadata)
	meta := AssetMetadata {
		input_ty,
		input_data_view,
		make([dynamic]PartialPath),
		make([dynamic]AssetTypeAndIdx),
		make([dynamic]AssetTypeAndIdx),
	}
	MANAGER.asset_metadata[asset] = meta
}

_set_dependencies :: proc(
	asset: AssetTypeAndIdx,
	new_file_dependencies: []PartialPath,
	new_dependencies: []AssetTypeAndIdx,
) {
	deps := _get_asset_deps(asset)

	// print("_set_dependencies", asset, deps.file_dependencies[:], "---->", new_file_dependencies)

	// remove old links:
	outer: for old_dep in deps.dependencies {
		old_dep_entry := _get_asset_deps(old_dep)
		for d, idx in old_dep_entry.dependants {
			if d == asset {
				// remove bidirectional link
				unordered_remove(&old_dep_entry.dependants, idx)
				continue outer
			}
		}
		fmt.panicf("{} not found in dependants of dependency {}", asset, old_dep)
	}
	clear(&deps.dependencies)

	// add new links:
	append(&deps.dependencies, ..new_dependencies)
	for new_dep in new_dependencies {
		new_dep_entry := _get_asset_deps(new_dep)
		append(&new_dep_entry.dependants, asset)
	}

	// remove old file links:
	outer2: for old_path in deps.file_dependencies {
		file_meta := _get_file_metadata(old_path)
		for d, idx in file_meta.dependants {
			if d == asset {
				unordered_remove(&file_meta.dependants, idx)
				continue outer2
			}
		}
		fmt.panicf("{} not found in dependants of file {}", asset, old_path)
	}

	clear(&deps.file_dependencies)
	append(&deps.file_dependencies, ..new_file_dependencies)
	for path in new_file_dependencies {
		file_meta := _get_file_metadata(path)
		append(&file_meta.dependants, asset)
	}
}

FileMetadata :: struct {
	full_path:     string,
	last_mod_time: time.Time,
	file_bytes:    Maybe([]u8), // only set if any of the assets registered here use a bytes loaded instead of a path loader
	dependants:    [dynamic]AssetTypeAndIdx,
}

// returns true if any changes were applied
hot_reload :: proc() -> bool {
	changed_partial_paths := _watched_files_that_changed()
	if len(changed_partial_paths) == 0 do return false

	now := time.now()
	reload_queue: [dynamic]AssetTypeAndIdx
	for partial_path in changed_partial_paths {
		meta := &MANAGER.file_cache[partial_path] or_else panic("should be in watched list")
		meta.last_mod_time = now
		full_path := meta.full_path

		// if the file metadata has some bytes loaded (byte loader registered), check if the bytes changed. Only reload if changed.
		// otherwise if bytes are nil, there are only assets with path loaders registered. In that case reload regardless.

		if old_file_bytes, ok := meta.file_bytes.([]u8); ok {
			// reload bytes
			file_bytes, read_ok := os.read_entire_file_from_filename(full_path)
			if !read_ok {
				fmt.eprintfln("could not read changed file at {}", full_path)
				delete(file_bytes)
				continue // no reload if file cannot be read!
			}
			file_bytes_equal := slice.equal(old_file_bytes, file_bytes)
			if file_bytes_equal {
				delete(file_bytes)
				continue // no reload if file bytes are equal!
			} else {
				delete(old_file_bytes)
				meta.file_bytes = file_bytes
			}
		} else {
			// always reload
		}

		// go through all assets that are directly derived from the bytes of this file and reload them:
		for asset in meta.dependants {
			append(&reload_queue, asset)
		}
	}

	// assets that need to be reloaded because they depend on assets that are directly derived from the files that were modified:
	for i := 0; i < len(reload_queue); i += 1 {
		asset := reload_queue[i]
		asset_meta := _get_asset_deps(asset)
		reload_err := _reload_asset(asset, asset_meta.input_ty, asset_meta.input_data_view)
		if reload_err, has_err := reload_err.(string); has_err {
			fmt.eprintfln(
				"Error reloading asset ({} -> {}): {}",
				asset_meta.input_ty,
				asset,
				reload_err,
			)
			continue
		}

		// put all dependants in queue too to reload them:
		next_dependant: for dependant in asset_meta.dependants {
			// if already in reload_queue don't add again:
			for el in reload_queue[i + 1:] {
				if el == dependant {
					continue next_dependant
				}
			}

			// input := INPUT
			append(&reload_queue, dependant)
		}

		// protect against infinite loops:
		if i > 1000 {
			panic("infinite reload loop")
		}
	}
	return len(reload_queue) > 0
}

// currently only for assets configured with input!!
_reload_asset :: proc(
	asset: AssetTypeAndIdx,
	input_ty: typeid,
	input_data: rawptr,
) -> (
	err: Error,
) {
	// print("_reload_asset", asset)
	if input_ty == {} || (input_data == nil && size_of(input_ty) > 0) {
		fmt.panicf("No input registered for asset {}. This should not happen!", asset)
	}

	slotmap: SlotmapPunned = MANAGER.storage[asset.asset_ty]
	scratch_ptr, _alloc_err := mem.alloc(slotmap.element_size, slotmap.element_align)
	assert(_alloc_err == .None)
	defer free(scratch_ptr)

	_push_load_scope()
	defer if err != nil do _pop_load_scope(asset, false)

	input_cache, has_input_cache :=
		MANAGER.input_caches[AssetAndInputType{asset.asset_ty, input_ty}]
	assert(has_input_cache)

	use_bytes_loader: bool = false
	loader: Loader
	if _loader, ok := input_cache.loader.(Loader); ok {
		loader = _loader
	} else {
		assert(input_ty == string)
		b_cache, has_b_cache := MANAGER.input_caches[AssetAndInputType{asset.asset_ty, []u8}]
		assert(has_b_cache)
		use_bytes_loader = true
		loader = b_cache.loader.(Loader) or_else panic("no bytes loader registered!")
	}
	_load_input_to_out(input_ty, input_data, loader, use_bytes_loader, scratch_ptr) or_return

	data_ptr := _slotmap_punned_data_ptr(slotmap, asset.idx)
	// drop the old value in place and put the new value in:
	if slotmap.drop_fn != nil {
		slotmap.drop_fn(data_ptr)
	}
	mem.copy_non_overlapping(data_ptr, scratch_ptr, slotmap.element_size)
	_pop_load_scope(asset, true)
	return nil
}

_slotmap_punned_data_ptr :: proc(slotmap: SlotmapPunned, idx: u32) -> rawptr {
	assert(idx < u32(len(slotmap.slots)))
	return rawptr(
		uintptr(raw_data(slotmap.slots)) +
		uintptr(idx) * slotmap.slot_size +
		slotmap.slot_data_offset,
	)
}

// file_bytes_hash :: proc(file_bytes: []u8) -> u64 {
// 	return hash.fnv64(file_bytes)
// }

// returns partial file path views in tmp array
_watched_files_that_changed :: proc() -> []PartialPath {
	changed := make([dynamic]PartialPath, context.temp_allocator)
	for partial_path, meta in MANAGER.file_cache {
		full_path := meta.full_path
		stats, stat_err := os.stat(full_path)
		if stat_err != nil {
			fmt.eprintfln("File {} cannot be checked: {}", full_path, stat_err)
			continue
		}
		if time.diff(meta.last_mod_time, stats.modification_time) > 0 {
			append(&changed, partial_path)
		}
	}
	return changed[:]
}


// /////////////////////////////////////////////////////////////////////////////
// SECTION: Slotmap
// /////////////////////////////////////////////////////////////////////////////

slotmap_punned_drop :: proc(slotmap: ^SlotmapPunned) {
	// drop all the elements in the slot map:
	if slotmap.drop_fn != nil {
		slots_start: uintptr = uintptr(raw_data(slotmap.slots))
		for i := 0; i < len(slotmap.slots); i += 1 {
			slot_ptr: uintptr = slots_start + slotmap.slot_size * uintptr(i)
			ref_count: u32 = (cast(^u32)slot_ptr)^
			if ref_count > 0 {
				slot_data_ptr := rawptr(slot_ptr + slotmap.slot_data_offset)
				slotmap.drop_fn(slot_data_ptr)
			}
		}
	}

	mem.free_with_size(raw_data(slotmap.slots), cap(slotmap.slots) * int(slotmap.slot_size))
	delete(slotmap.free_list)
}


Handle :: struct($T: typeid) {
	idx: u32,
}

SlotmapPunned :: struct {
	slots:            [dynamic]struct{},
	slot_size:        uintptr,
	slot_data_offset: uintptr,
	free_list:        [dynamic]u32,
	drop_fn:          proc(this: rawptr), // nullable
	element_size:     int,
	element_align:    int,
}

Slotmap :: struct($T: typeid) {
	slots:            [dynamic]Slot(T),
	slot_size:        uintptr,
	slot_data_offset: uintptr,
	free_list:        [dynamic]u32,
	drop_fn:          proc(this: ^T), // nullable
	element_size:     int,
	element_align:    int,
}

Slot :: struct($T: typeid) {
	ref_count: u32, // if zero, this is an empty slot
	data:      T,
}

PartialPath :: distinct string


AbsolutePath :: struct {}

slotmap_create :: proc($T: typeid, drop_fn: proc(this: ^T)) -> Slotmap(T) {
	return Slotmap(T) {
		slots = make([dynamic]Slot(T)),
		slot_size = size_of(Slot(T)),
		slot_data_offset = offset_of(Slot(T), data),
		free_list = make([dynamic]u32),
		drop_fn = drop_fn,
		element_size = size_of(T),
		element_align = align_of(T),
	}
}

slotmap_clone_handle :: proc(slotmap: ^Slotmap($T), handle: Handle(T)) {
	slot: ^Slot(T) = &slotmap.slots[handle.idx]
	assert(slot.ref_count > 0)
	slot.ref_count += 1
}


slotmap_get_ref :: proc(slotmap: ^Slotmap($T), handle: Handle(T)) -> ^T {
	slot: ^Slot(T) = &slotmap.slots[handle.idx]
	assert(slot.ref_count > 0)
	return &slot.data
}

slotmap_get :: proc(slotmap: Slotmap($T), handle: Handle(T)) -> T {
	slot: Slot(T) = slotmap.slots[handle.idx]
	assert(slot.ref_count > 0)
	return slot.data
}

slotmap_get_ref_count :: proc(slotmap: Slotmap($T), handle: Handle(T)) -> u32 {
	slot: Slot(T) = slotmap.slots[handle.idx]
	assert(slot.ref_count > 0)
	return slot.ref_count
}

// returns true if ref count reduced to 0
slotmap_remove :: proc(slotmap: ^Slotmap($T), handle: Handle(T)) {
	slot: ^Slot(T) = &slotmap.slots[handle.idx]
	assert(slot.ref_count > 0)
	slot.ref_count -= 1
	if slot.ref_count == 0 {
		asset_ctx := _new_asset_context()
		if drop_fn, has_drop_fn := slotmap.drop_fn.?; has_drop_fn {
			drop_fn(&slot.data, asset_ctx)
		}
		slot.data = {}
		append(&slotmap.free_list, handle.idx)
		return true
	}
	return false
}

slotmap_insert :: proc(slotmap: ^Slotmap($T), data: T) -> Handle(T) {
	if len(slotmap.free_list) > 0 {
		idx := pop(&slotmap.free_list)
		slot: ^Slot(T) = &slotmap.slots[idx]
		assert(slot.ref_count == 0)
		slot.ref_count = 1
		slot.data = data
		return Handle(T){idx}
	} else {
		handle := Handle(T){u32(len(slotmap.slots))}
		append(&slotmap.slots, Slot(T){ref_count = 1, data = data})
		return handle
	}
}
