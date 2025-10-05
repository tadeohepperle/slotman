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

// returns true if this was the last reference
remove :: proc(handle: Handle($T)) -> bool {
	return slotmap_remove(get_slotmap_ref(T), handle)
}

clone_handle :: proc(handle: Handle($T)) {
	slotmap_clone_handle(get_slotmap_ref(T), handle)
}

load_from_path :: proc($T: typeid, path: string) -> Handle(T) {
	res, err := try_load_from_path(T, path)
	asset_ty: typeid = T
	if err, has_err := err.(string); has_err {
		fmt.panicf("Could not load asset {} from path {}: {}", asset_ty, path, err)
	}
	return res
}

load_from_input :: proc($T: typeid, input: any) -> Handle(T) {
	asset_ty: typeid = T
	handle, err := try_load_from_input(T, input)
	if err, has_err := err.(string); has_err {
		fmt.panicf("Could not load asset {} from input {}: {}", asset_ty, input, err)
	}
	return handle
}

try_load_from_input :: proc($T: typeid, input: any) -> (handle: Handle(T), err: Error) {
	_push_load_scope()
	defer if err != nil do _pop_load_scope(nil)

	res: T = _load_from_input_typed(T, input) or_return
	slotmap: ^Slotmap(T) = get_slotmap_ref(T)
	handle = slotmap_insert(slotmap, res)
	asset := AssetTypeAndIdx{T, handle.idx}
	_insert_asset_metadata(asset, input)
	_pop_load_scope(asset)

	return handle, nil
}

_insert_asset_metadata :: proc(asset: AssetTypeAndIdx, input: any) {
	_, meta, just_inserted, _ := map_entry(&MANAGER.asset_meta, asset)
	assert(just_inserted)
	meta.dependencies = make([dynamic]AssetTypeAndIdx)
	meta.dependants = make([dynamic]AssetTypeAndIdx)

	if meta.input.ptr != nil {
		mem.free(meta.input.ptr)
	}
	input_ty: typeid = input.id
	input_ti := type_info_of(input_ty)

	boxed_input_ptr: rawptr = nil
	if input_ti.size > 0 {
		boxed_input_ptr = mem.alloc(input_ti.size, input_ti.align) or_else panic("alloc err")
		mem.copy_non_overlapping(boxed_input_ptr, input.data, input_ti.size)
	}
	meta.input = BoxedAny{boxed_input_ptr, input_ty}
}

try_load_from_path :: proc($T: typeid, partial_path: string) -> (handle: Handle(T), err: Error) {
	asset_ty: typeid = T
	partial_path := PartialPath(partial_path)
	_push_load_scope()
	defer if err != nil do _pop_load_scope(nil)
	// if an asset is already loaded for this path of this type, there is no need to load it again:
	key_ptr, meta, just_inserted, _alloc_err := map_entry(&MANAGER.file_map, partial_path)
	if just_inserted {
		defer if err != nil {
			delete_key(&MANAGER.file_map, partial_path)
		}
		stat, found_full_path := find_full_asset_path(partial_path)
		if !found_full_path {
			return {}, fmt.tprint("could not find full path for partial path {}", partial_path)
		}

		meta.full_path = strings.clone(stat.fullpath)
		meta.last_mod_time = stat.modification_time
		key_ptr^ = PartialPath(strings.clone(string(partial_path)))
	} else {
		// if this asset type is already loaded for this path, just return it (incrementing ref count)
		for asset in meta.assets {
			if asset.asset_ty == T {
				handle = Handle(T){asset.idx}
				clone_handle(handle)
				_pop_load_scope(asset, set_dependencies = false) // do not set dependencies because asset was not really loaded
				return handle, nil
			}
		}
	}

	// parse data from bytes and insert into slotmap:
	data: T = _load_from_bytes_or_path_typed(T, meta) or_return
	slotmap: ^Slotmap(T) = get_slotmap_ref(T)
	handle = slotmap_insert(slotmap, data)

	// get again, because could have moved if other assets were loaded in load_from_bytes!
	meta2 := &MANAGER.file_map[partial_path] or_else panic("should have meta!")
	for a in meta2.assets do assert(a.asset_ty != T)
	asset := AssetTypeAndIdx{T, handle.idx}
	append(&meta2.assets, asset)
	_insert_asset_metadata(asset, partial_path)
	_pop_load_scope(asset)
	return handle, nil
}

_load_from_bytes_or_path_typed :: proc($T: typeid, meta: ^FileMetadata) -> (res: T, err: Error) {
	asset_ty: typeid = T
	if bytes_loader, ok := MANAGER.loaders[AssetLoaderTypePair{asset_ty, []u8}]; ok {
		// load from file bytes:
		if meta.file_bytes == nil {
			file_bytes, read_ok := os.read_entire_file_from_filename(meta.full_path)
			if !read_ok {
				return {}, fmt.tprintf("could not read file at {}", meta.full_path)
			}
			meta.file_bytes = file_bytes
		}
		file_bytes := meta.file_bytes.([]u8)
		loader_load(bytes_loader, &file_bytes, &res) or_return
	} else if path_loader, ok := MANAGER.loaders[AssetLoaderTypePair{asset_ty, string}]; ok {
		// load from path directly:
		assert(meta.full_path != "")
		loader_load(path_loader, &meta.full_path, &res) or_return
	} else {
		return {}, fmt.tprintf("No bytes loader or path loader registered for {}!", asset_ty)
	}
	return res, nil
}

_load_from_bytes_or_path_punned :: proc(
	asset_ty: typeid,
	meta: ^FileMetadata,
	out: rawptr,
) -> (
	err: Error,
) {
	if bytes_loader, ok := MANAGER.loaders[AssetLoaderTypePair{asset_ty, []u8}]; ok {
		// load from file bytes:
		if meta.file_bytes == nil {
			file_bytes, read_ok := os.read_entire_file_from_filename(meta.full_path)
			if !read_ok {
				return fmt.tprintf("could not read file at {}", meta.full_path)
			}
			meta.file_bytes = file_bytes
		}
		file_bytes := meta.file_bytes.([]u8)
		loader_load(bytes_loader, &file_bytes, out) or_return
	} else if path_loader, ok := MANAGER.loaders[AssetLoaderTypePair{asset_ty, string}]; ok {
		// load from path directly:
		assert(meta.full_path != "")
		loader_load(path_loader, &meta.full_path, out) or_return
	} else {
		return fmt.tprintf("No bytes loader or path loader registered for {}!", asset_ty)
	}
	return nil
}

_load_from_input_typed :: proc($T: typeid, input: any) -> (res: T, err: Error) {
	asset_ty: typeid = T
	input_ty: typeid = input.id
	loader, has_loader := MANAGER.loaders[AssetLoaderTypePair{asset_ty, input_ty}]
	if !has_loader {
		return {}, fmt.tprintf("no input loader ({} -> {}) registered!", input_ty, asset_ty)
	}
	loader_load(loader, input.data, &res) or_return
	return res, nil
}

_load_from_input_punned :: proc(asset_ty: typeid, input: any, out: rawptr) -> (err: Error) {
	input_ty: typeid = input.id
	loader, has_loader := MANAGER.loaders[AssetLoaderTypePair{asset_ty, input_ty}]
	if !has_loader {
		return fmt.tprintf("no input loader ({} -> {}) registered!", input_ty, asset_ty)
	}
	return loader_load(loader, input.data, out)
}

insert :: proc(asset: $T) -> Handle(T) {
	slotmap: ^Slotmap(T) = get_slotmap_ref()
	return slotmap_insert(asset)
}

get_slotmap_ref :: proc($T: typeid) -> ^Slotmap(T) {
	asset_ty: typeid = T
	slotmap: ^SlotmapPunned =
		&MANAGER.maps[asset_ty] or_else fmt.panicf("asset type {} not registered!", asset_ty)
	return cast(^Slotmap(T))slotmap
}

get_slotmap :: proc($T: typeid) -> Slotmap(T) {
	return get_slotmap_ref(T)^
}

// returns in tmp!
find_full_asset_path :: proc(partial_path: PartialPath) -> (stat: os.File_Info, ok: bool) {
	for dir in MANAGER.asset_directories {
		full_path := fmt.tprintf("{}{}", dir, partial_path)
		stat := os.stat(full_path, context.temp_allocator) or_continue
		return stat, true
	}
	return {}, false
}

// drop is nullable!
register_asset_type :: proc($T: typeid, drop: proc(this: ^T) = nil) {
	assert(!MANAGER.frozen, "Cannot register asset type after freezing manager!")
	asset_ty: typeid = T
	if asset_ty in MANAGER.maps {
		fmt.eprintfln("Asset type {} already registered!", asset_ty)
		return
	}
	MANAGER.maps[asset_ty] = transmute(SlotmapPunned)slotmap_create(T, drop)
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
	register_loader(T, []u8, from_bytes)
}

register_loader :: proc(
	$T: typeid,
	$I: typeid,
	load_fn: proc(input: I) -> (this: T, error: Error),
) {
	when I == PartialPath {
		fmt.panicf(
			"Loaders for PartialPath cannot be registered, register loader from []u8 instead",
		)
	}

	asset_ty: typeid = T
	input_ty: typeid = I

	if asset_ty not_in MANAGER.maps {
		fmt.panicf(
			"Cannot register loader for asset type {} because there is no map for it yet!",
			asset_ty,
		)
	}

	assert(asset_ty in MANAGER.maps, "Cannot register loader")
	assert(!MANAGER.frozen, "Cannot register asset loader after freezing manager!")

	pair := AssetLoaderTypePair {
		asset_ty = asset_ty,
		input_ty = input_ty,
	}
	if pair in MANAGER.loaders {
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

	MANAGER.loaders[pair] = Loader {
		original_load_fn = cast(rawptr)load_fn,
		punned_load_fn   = punned_load_fn,
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


AssetLoaderTypePair :: struct {
	asset_ty: typeid,
	input_ty: typeid,
}

AssetTypeAndIdx :: struct {
	asset_ty: typeid,
	idx:      u32,
}

BoxedAny :: struct {
	ptr: rawptr,
	ty:  typeid,
}

// TODO: use a perfect hash function to replace map[typeid]SlotmapPunned with []SlotmapPunned

// @(private)
MANAGER: Manager
Manager :: struct {
	frozen:            bool,
	asset_directories: [dynamic]string,
	loaders:           map[AssetLoaderTypePair]Loader,
	maps:              map[typeid]SlotmapPunned,
	// maps partial path to full path, bytes and all assets that were loaded from it
	file_map:          map[PartialPath]FileMetadata,
	load_scopes:       [dynamic]LoadScope,
	asset_meta:        map[AssetTypeAndIdx]AssetMetadata,
}

@(private)
_asset_manager_drop :: proc(manager: ^Manager) {
	delete(manager.loaders)
	manager.loaders = {}

	for ty, &slotmap in manager.maps {
		slotmap_punned_drop(&slotmap)
	}
	delete(manager.maps)
	manager.maps = {}

	for path in manager.asset_directories {
		delete(path)
	}
	delete(manager.asset_directories)
	manager.asset_directories = {}

	for partial_path, meta in manager.file_map {
		delete(string(partial_path))
		delete(meta.full_path)
		if file_bytes, ok := meta.file_bytes.([]u8); ok {
			delete(file_bytes)
		}
		delete(meta.assets)
	}
	manager.file_map = {}

	for l in manager.load_scopes {
		delete(l.dependencies)
	}
	delete(manager.load_scopes)
	manager.load_scopes = {}

	for asset, meta in manager.asset_meta {
		delete(meta.dependants)
		delete(meta.dependants)
		if meta.input.ptr != nil {
			free(meta.input.ptr)
		}
	}
	delete(manager.asset_meta)
	manager.asset_meta = {}
}

AssetMetadata :: struct {
	input:        BoxedAny,
	dependencies: [dynamic]AssetTypeAndIdx,
	dependants:   [dynamic]AssetTypeAndIdx,
}

LoadScope :: struct {
	dependencies: [dynamic]AssetTypeAndIdx,
}

_push_load_scope :: proc() {
	load_scope := LoadScope {
		dependencies = make([dynamic]AssetTypeAndIdx),
	}
	append(&MANAGER.load_scopes, load_scope)
}

_pop_load_scope :: proc(asset: Maybe(AssetTypeAndIdx), set_dependencies: bool = true) {
	assert(len(MANAGER.load_scopes) > 0)
	load_scope := pop(&MANAGER.load_scopes)

	// print("--- called _pop_load_scope for", asset, load_scope.dependencies[:])
	defer delete(load_scope.dependencies)
	if asset, ok := asset.(AssetTypeAndIdx); ok {
		if set_dependencies {
			_set_dependencies(asset, load_scope.dependencies[:])
		}
		// add this asset as dependency to parent scope where this function was called
		if len(MANAGER.load_scopes) > 0 {
			parent_scope := &MANAGER.load_scopes[len(MANAGER.load_scopes) - 1]

			print("attach to parent scope")
			if !slice.any_of(parent_scope.dependencies[:], asset) {
				append(&parent_scope.dependencies, asset)
			}
		}
	}

}

_get_asset_metadata :: proc(asset: AssetTypeAndIdx) -> ^AssetMetadata {
	meta, ok := &MANAGER.asset_meta[asset]
	assert(ok)
	return meta
}

_set_dependencies :: proc(asset: AssetTypeAndIdx, new_dependencies: []AssetTypeAndIdx) {
	meta := _get_asset_metadata(asset)

	// remove old links:
	outer: for old_dep in meta.dependencies {
		old_dep_entry := _get_asset_metadata(old_dep)
		for d, idx in old_dep_entry.dependants {
			if d == asset {
				// remove bidirectional link
				unordered_remove(&old_dep_entry.dependants, idx)
				continue outer
			}
		}
		fmt.panicf("{} not found in dependants of dependency {}", asset, old_dep)
	}
	clear(&meta.dependencies)

	// add new links:
	append(&meta.dependencies, ..new_dependencies)
	for new_dep in new_dependencies {
		new_dep_entry := _get_asset_metadata(new_dep)
		append(&new_dep_entry.dependants, asset)
	}

	// print("------------ set dependencies", asset)
	// print(MANAGER.asset_meta)
}

FileMetadata :: struct {
	full_path:     string,
	last_mod_time: time.Time,
	file_bytes:    Maybe([]u8), // only set if any of the assets registered here use a bytes loaded instead of a path loader
	// all assets in here should have a from_bytes loader configured!
	assets:        [dynamic]AssetTypeAndIdx,
}

hot_reload :: proc() {
	changed_partial_paths := _watched_files_that_changed()
	if len(changed_partial_paths) == 0 do return

	now := time.now()
	reload_queue: [dynamic]AssetTypeAndIdx
	for partial_path in changed_partial_paths {
		meta := &MANAGER.file_map[partial_path] or_else panic("should be in watched list")
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
		for asset in meta.assets {
			append(&reload_queue, asset)
		}
	}

	// assets that need to be reloaded because they depend on assets that are directly derived from the files that were modified:
	for i := 0; i < len(reload_queue); i += 1 {
		asset := reload_queue[i]
		asset_meta := _get_asset_metadata(asset)
		if reload_err, has_err := _reload_asset(asset, asset_meta.input).(string); has_err {
			fmt.eprintfln(
				"Error reloading asset {} from {}: {}",
				asset,
				asset_meta.input.ty,
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
}

// currently only for assets configured with input!!
_reload_asset :: proc(asset: AssetTypeAndIdx, input: BoxedAny) -> (err: Error) {
	meta, has_meta := MANAGER.asset_meta[asset]
	assert(has_meta, "Cannot reload asset, meta is not registered!")

	if meta.input.ty == {} || (meta.input.ptr == nil && size_of(meta.input.ty) > 0) {
		fmt.panicf("No input registered for asset {}. This should not happen!", asset)
	}

	slotmap: SlotmapPunned = MANAGER.maps[asset.asset_ty]
	scratch_ptr, _alloc_err := mem.alloc(slotmap.element_size, slotmap.element_align)
	assert(_alloc_err == .None)
	defer free(scratch_ptr)

	_push_load_scope()
	if meta.input.ty == PartialPath {
		partial_path: PartialPath = (cast(^PartialPath)meta.input.ptr)^
		file_meta: FileMetadata =
			MANAGER.file_map[partial_path] or_else panic("partial path not in map")
		_load_from_bytes_or_path_punned(asset.asset_ty, &file_meta, scratch_ptr) or_return
	} else {
		_load_from_input_punned(
			asset.asset_ty,
			mem.make_any(meta.input.ptr, meta.input.ty),
			scratch_ptr,
		) or_return
	}

	data_ptr := _slotmap_punned_data_ptr(slotmap, asset.idx)
	// drop the old value in place and put the new value in:
	if slotmap.drop_fn != nil {
		slotmap.drop_fn(data_ptr)
	}
	mem.copy_non_overlapping(data_ptr, scratch_ptr, slotmap.element_size)
	_pop_load_scope(asset)
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
	for partial_path, meta in MANAGER.file_map {
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
