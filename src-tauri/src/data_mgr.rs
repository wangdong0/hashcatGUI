// src-tauri/src/import_export.rs

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};
use std::io::{Cursor, Read, Write};
use std::env::temp_dir;
use zip::write::FileOptions;
use zip::ZipWriter;
use tempfile::tempdir;
use walkdir::WalkDir;
use md5;
use std::io::BufReader;

/// 获取应用程序执行文件所在目录
fn get_app_exe_dir(_app: &AppHandle) -> Result<PathBuf, String> {
    // 获取当前执行文件的路径
    let exe_path = std::env::current_exe()
        .map_err(|err| format!("获取执行文件路径失败：{}", err))?;
    
    // 获取执行文件所在目录
    let exe_dir = exe_path.parent()
        .ok_or_else(|| "无法获取执行文件目录".to_string())?;
    
    Ok(exe_dir.to_path_buf())
}

/// 标准化路径分隔符（统一使用 /）
fn normalize_path(path: &str) -> String {
    path.replace("\\", "/")
}

// ==================== 数据结构定义 ====================

/// 预设配置结构（用于导入导出）
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresetConfig {
    pub id: String,
    pub name: String,
    pub description: String,
    pub attack_mode: u8,
    pub hash_mode: Option<String>,
    pub dictionary_path: Option<String>,
    pub dictionary_path2: Option<String>,
    #[serde(default)]
    pub dictionary_paths: Vec<String>,
    pub mask: Option<String>,
    pub mask_path: Option<String>,
    pub prefix_mask: Option<String>,
    pub suffix_mask: Option<String>,
    pub use_rules: Option<bool>,
    pub use_left_rule: Option<bool>,
    pub left_rule: Option<String>,
    pub use_right_rule: Option<bool>,
    pub right_rule: Option<String>,
    #[serde(default)]
    pub custom_charsets: HashMap<String, String>,
    pub increment: Option<bool>,
    pub increment_min: Option<String>,
    pub increment_max: Option<String>,
    #[serde(default)]
    pub rule_paths: Vec<String>,
    pub created_at: String,
}

/// 预设分组结构
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresetGroup {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub preset_ids: Vec<String>,
    pub expanded: bool,
}

/// 自定义资源结构
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomResource {
    pub id: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub name: String,
    pub description: String,
    pub mask: Option<String>,
    pub prefix_mask: Option<String>,
    pub suffix_mask: Option<String>,
    pub charset_slot: Option<String>,
    pub charset_value: Option<String>,
    pub path: Option<String>,
    pub size: Option<u64>,
    pub created_at: String,
    pub candidates: Option<u64>,
    pub is_builtin_copy: Option<bool>,
    pub rule_type: Option<String>,
    pub rule_value: Option<String>,
    pub sort_order: Option<i32>,
}

/// 资源分组结构
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceGroup {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub resource_ids: Vec<String>,
    pub expanded: bool,
}

/// 导出数据结构
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportData {
    version: String,
    #[serde(rename = "type")]
    r#type: String,
    export_name: String,
    groups: Vec<serde_json::Value>,
    items: Vec<serde_json::Value>,
}

/// 导入预览数据结构
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreviewData {
    pub version: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub group_count: usize,
    pub item_count: usize,
    pub groups: Vec<PreviewGroupInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewGroupInfo {
    pub id: String,
    pub name: String,
    pub item_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub success: bool,
    pub message: String,
    pub imported_groups: usize,
    pub imported_items: usize,
    pub conflicts: Vec<ConflictInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictInfo {
    pub id: String,
    pub name: String,
    pub r#type: String, // "preset" 或 "group"
    pub existing_name: Option<String>,
    pub group_id: Option<String>,   // 新增：预设所属的分组ID
    pub group_name: Option<String>, // 新增：预设所属的分组名称
}


/// 预览预设导入（检查冲突但不执行导入）
#[tauri::command]
pub fn preview_import_presets(
    app: AppHandle,
    folder_path: String,
) -> Result<ImportResult, String> {
    let folder = PathBuf::from(folder_path);
    let data_dir = folder.join("data");
    
    // 读取导出数据
    let export_json_path = data_dir.join("export.json");
    if !export_json_path.is_file() {
        return Err("无效的导出文件夹".into());
    }
    
    let content = fs::read_to_string(&export_json_path)
        .map_err(|err| format!("读取 export.json 失败：{}", err))?;
    
    let export_data: ExportData = serde_json::from_str(&content)
        .map_err(|err| format!("解析 export.json 失败：{}", err))?;
    
    if export_data.r#type != "preset" {
        return Err("导出数据类型不匹配：期望预设数据".into());
    }
    
    // 处理预设数据（保留原始ID）
    let mut processed_presets: Vec<PresetConfig> = Vec::new();
    for item_value in &export_data.items {
        let mut preset: PresetConfig = serde_json::from_value(item_value.clone())
            .map_err(|err| format!("解析预设数据失败：{}", err))?;
        processed_presets.push(preset);
    }
    
    // 处理分组数据（保留原始ID）
    let mut processed_groups: Vec<PresetGroup> = Vec::new();
    for group_value in &export_data.groups {
        let group: PresetGroup = serde_json::from_value(group_value.clone())
            .map_err(|err| format!("解析分组数据失败：{}", err))?;
        processed_groups.push(group);
    }
    
    // 读取现有数据
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    
    let presets_path = app_data_dir.join("presets.json");
    let groups_path = app_data_dir.join("preset_groups.json");
    
    let existing_presets: Vec<PresetConfig> = if presets_path.is_file() {
        let existing_content = fs::read_to_string(&presets_path).map_err(|err| err.to_string())?;
        serde_json::from_str(&existing_content).unwrap_or_default()
    } else {
        Vec::new()
    };
    
    let existing_groups: Vec<PresetGroup> = if groups_path.is_file() {
        let existing_content = fs::read_to_string(&groups_path).map_err(|err| err.to_string())?;
        serde_json::from_str(&existing_content).unwrap_or_default()
    } else {
        Vec::new()
    };
    
    // 检测冲突
    let mut conflicts: Vec<ConflictInfo> = Vec::new();
    
    // 检查预设冲突
    let existing_preset_ids: HashSet<String> = existing_presets.iter().map(|p| p.id.clone()).collect();
    for preset in &processed_presets {
        if existing_preset_ids.contains(&preset.id) {
            let existing = existing_presets.iter().find(|p| p.id == preset.id);
            
            // 找到预设所属的分组
            let group_id = processed_groups.iter()
                .find(|g| g.preset_ids.contains(&preset.id))
                .map(|g| g.id.clone());
            let group_name = processed_groups.iter()
                .find(|g| g.preset_ids.contains(&preset.id))
                .map(|g| g.name.clone());
            
            conflicts.push(ConflictInfo {
                id: preset.id.clone(),
                name: preset.name.clone(),
                r#type: "preset".to_string(),
                existing_name: existing.map(|e| e.name.clone()),
                group_id,      // 新增
                group_name,    // 新增
            });
        }
    }
    
    // 检查分组冲突
    let existing_group_ids: HashSet<String> = existing_groups.iter().map(|g| g.id.clone()).collect();
    for group in &processed_groups {
        if existing_group_ids.contains(&group.id) {
            let existing = existing_groups.iter().find(|g| g.id == group.id);
            conflicts.push(ConflictInfo {
                id: group.id.clone(),
                name: group.name.clone(),
                r#type: "group".to_string(),
                existing_name: existing.map(|e| e.name.clone()),
                group_id: None,      // 新增：分组本身没有所属分组，设为 None
                group_name: None,    // 新增：分组本身没有所属分组，设为 None
            });
        }
    }
    
    Ok(ImportResult {
        success: true,
        message: if conflicts.is_empty() { "无冲突".to_string() } else { "检测到冲突".to_string() },
        imported_groups: processed_groups.len(),
        imported_items: processed_presets.len(),
        conflicts,
    })
}


/// 预览自定义资源导入（检查冲突但不执行导入）
#[tauri::command]
pub fn preview_import_resources(
    app: AppHandle,
    folder_path: String,
) -> Result<ImportResult, String> {
    let folder = PathBuf::from(folder_path);
    let data_dir = folder.join("data");
    
    // 读取导出数据
    let export_json_path = data_dir.join("export.json");
    if !export_json_path.is_file() {
        return Err("无效的导出文件夹".into());
    }
    
    let content = fs::read_to_string(&export_json_path)
        .map_err(|err| format!("读取 export.json 失败：{}", err))?;
    
    let export_data: ExportData = serde_json::from_str(&content)
        .map_err(|err| format!("解析 export.json 失败：{}", err))?;
    
    if export_data.r#type != "custom" {
        return Err("导出数据类型不匹配：期望自定义资源数据".into());
    }
    
    // 处理资源数据（保留原始ID）
    let mut processed_resources: Vec<CustomResource> = Vec::new();
    for item_value in &export_data.items {
        let resource: CustomResource = serde_json::from_value(item_value.clone())
            .map_err(|err| format!("解析资源数据失败：{}", err))?;
        processed_resources.push(resource);
    }
    
    // 处理分组数据（保留原始ID）
    let mut processed_groups: Vec<ResourceGroup> = Vec::new();
    for group_value in &export_data.groups {
        let group: ResourceGroup = serde_json::from_value(group_value.clone())
            .map_err(|err| format!("解析分组数据失败：{}", err))?;
        processed_groups.push(group);
    }
    
    // 读取现有数据
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    
    let resources_path = app_data_dir.join("custom_resources.json");
    let groups_path = app_data_dir.join("resource_groups.json");
    
    let existing_resources: Vec<CustomResource> = if resources_path.is_file() {
        let existing_content = fs::read_to_string(&resources_path).map_err(|err| err.to_string())?;
        serde_json::from_str(&existing_content).unwrap_or_default()
    } else {
        Vec::new()
    };
    
    let existing_groups: Vec<ResourceGroup> = if groups_path.is_file() {
        let existing_content = fs::read_to_string(&groups_path).map_err(|err| err.to_string())?;
        serde_json::from_str(&existing_content).unwrap_or_default()
    } else {
        Vec::new()
    };
    
    // 检测冲突
    let mut conflicts: Vec<ConflictInfo> = Vec::new();
    
    // 检查资源冲突
    let existing_resource_ids: HashSet<String> = existing_resources.iter().map(|r| r.id.clone()).collect();
    for resource in &processed_resources {
        if existing_resource_ids.contains(&resource.id) {
            let existing = existing_resources.iter().find(|r| r.id == resource.id);
            
            // 找到资源所属的分组
            let group_id = processed_groups.iter()
                .find(|g| g.resource_ids.contains(&resource.id))
                .map(|g| g.id.clone());
            let group_name = processed_groups.iter()
                .find(|g| g.resource_ids.contains(&resource.id))
                .map(|g| g.name.clone());
            
            conflicts.push(ConflictInfo {
                id: resource.id.clone(),
                name: resource.name.clone(),
                r#type: "preset".to_string(),
                existing_name: existing.map(|e| e.name.clone()),
                group_id,
                group_name,
            });
        }
    }
    
    // 检查分组冲突
    let existing_group_ids: HashSet<String> = existing_groups.iter().map(|g| g.id.clone()).collect();
    for group in &processed_groups {
        if existing_group_ids.contains(&group.id) {
            let existing = existing_groups.iter().find(|g| g.id == group.id);
            conflicts.push(ConflictInfo {
                id: group.id.clone(),
                name: group.name.clone(),
                r#type: "group".to_string(),
                existing_name: existing.map(|e| e.name.clone()),
                group_id: None,
                group_name: None,
            });
        }
    }
    
    Ok(ImportResult {
        success: true,
        message: if conflicts.is_empty() { "无冲突".to_string() } else { "检测到冲突".to_string() },
        imported_groups: processed_groups.len(),
        imported_items: processed_resources.len(),
        conflicts,
    })
}

// ==================== 导出功能 ====================

/// 查找可用的导出目录名（处理冲突）
/// 如果导出名称已存在，则尝试 "名称-1", "名称-2" 等
fn find_available_export_dir(target_path: &Path, export_name: &str) -> PathBuf {
    let mut export_dir = target_path.join(export_name);
    let mut counter = 1;
    
    while export_dir.exists() {
        export_dir = target_path.join(format!("{}-{}", export_name, counter));
        counter += 1;
    }
    
    export_dir
}

/// 查找可用的 ZIP 文件路径（处理冲突）
fn find_available_zip_path(target_path: &Path, export_name: &str) -> PathBuf {
    let mut zip_path = target_path.join(format!("{}.zip", export_name));
    let mut counter = 1;
    
    while zip_path.exists() {
        zip_path = target_path.join(format!("{}-{}.zip", export_name, counter));
        counter += 1;
    }
    
    zip_path
}

/// 导出预设分组
#[tauri::command]
pub fn export_presets(
    preset_groups_json: String,
    presets_json: String,
    selected_group_ids: Vec<String>,
    target_dir: String,
    export_name: String,
) -> Result<(), String> {
    // 解析传入的预设分组数据
    let all_groups: Vec<PresetGroup> = serde_json::from_str(&preset_groups_json)
        .map_err(|err| format!("解析预设分组数据失败：{}", err))?;
    
    // 解析传入的预设数据
    let all_presets: Vec<PresetConfig> = serde_json::from_str(&presets_json)
        .map_err(|err| format!("解析预设数据失败：{}", err))?;
    
    // 筛选选中的分组
    let selected_groups: Vec<PresetGroup> = all_groups
        .into_iter()
        .filter(|g| selected_group_ids.contains(&g.id))
        .collect();
    
    if selected_groups.is_empty() {
        return Err("请选择至少一个分组".into());
    }
    
    // 收集选中分组中的所有预设ID
    let selected_preset_ids: HashSet<String> = selected_groups
        .iter()
        .flat_map(|g| g.preset_ids.iter().cloned())
        .collect();
    
    // 筛选选中的预设
    let selected_presets: Vec<PresetConfig> = all_presets
        .into_iter()
        .filter(|p| selected_preset_ids.contains(&p.id))
        .collect();
    
    // 创建导出目录结构
    let target_path = PathBuf::from(target_dir);
    // 查找可用的导出目录名（处理冲突）
    let export_dir = find_available_export_dir(&target_path, &export_name);
    let data_dir = export_dir.join("data");
    let files_dir = export_dir.join("files");

    fs::create_dir_all(&export_dir).map_err(|err| format!("创建导出目录失败：{}", err))?;
    fs::create_dir_all(&data_dir).map_err(|err| format!("创建数据目录失败：{}", err))?;
    fs::create_dir_all(&files_dir).map_err(|err| format!("创建文件目录失败：{}", err))?;
    
    // 收集所有预设引用的文件路径
    let all_file_paths = collect_preset_file_paths(&selected_presets);
    
    // 复制文件并生成路径映射（去重）
    let path_mapping = copy_files_with_dedup(&all_file_paths, &files_dir)?;
    
    // 更新预设中的路径引用
    let processed_presets = update_preset_paths(&selected_presets, &path_mapping);
    
    // 转换为 Value 类型以便序列化
    let groups_value: Vec<serde_json::Value> = selected_groups
        .into_iter()
        .map(|g| serde_json::to_value(g).unwrap())
        .collect();
    
    let items_value: Vec<serde_json::Value> = processed_presets
        .into_iter()
        .map(|p| serde_json::to_value(p).unwrap())
        .collect();
    
    // 生成导出数据
    let export_data = ExportData {
        version: "1.0".to_string(),
        r#type: "preset".to_string(),
        export_name: export_name.clone(),
        groups: groups_value,
        items: items_value,
    };
    
    // 保存导出数据
    write_json(&data_dir.join("export.json"), &export_data)?;
    
    // 保存路径映射（如果有）
    if !path_mapping.is_empty() {
        write_json(&data_dir.join("path-mapping.json"), &path_mapping)?;
    }

    // 将导出文件夹打包为压缩文件（处理 ZIP 文件名冲突）
    let zip_path = find_available_zip_path(&target_path, &export_name);
    create_zip(&export_dir, &zip_path)?;

    // 打包完成后删除源文件夹
    fs::remove_dir_all(&export_dir)
        .map_err(|err| format!("删除源文件夹失败：{}", err))?;
    
    Ok(())
}

/// 导出自定义资源分组
#[tauri::command]
pub fn export_resources(
    resource_groups_json: String,
    resources_json: String,
    selected_group_ids: Vec<String>,
    target_dir: String,
    export_name: String,
) -> Result<(), String> {
    // 解析传入的资源分组数据
    let all_groups: Vec<ResourceGroup> = serde_json::from_str(&resource_groups_json)
        .map_err(|err| format!("解析资源分组数据失败：{}", err))?;
    
    // 解析传入的资源数据
    let all_resources: Vec<CustomResource> = serde_json::from_str(&resources_json)
        .map_err(|err| format!("解析资源数据失败：{}", err))?;
    
    // 筛选选中的分组
    let selected_groups: Vec<ResourceGroup> = all_groups
        .into_iter()
        .filter(|g| selected_group_ids.contains(&g.id))
        .collect();
    
    if selected_groups.is_empty() {
        return Err("请选择至少一个分组".into());
    }
    
    // 收集选中分组中的所有资源ID
    let selected_resource_ids: HashSet<String> = selected_groups
        .iter()
        .flat_map(|g| g.resource_ids.iter().cloned())
        .collect();
    
    // 筛选选中的资源
    let selected_resources: Vec<CustomResource> = all_resources
        .into_iter()
        .filter(|r| selected_resource_ids.contains(&r.id))
        .collect();
    
    // 创建导出目录结构
    let target_path = PathBuf::from(target_dir);
    // 查找可用的导出目录名（处理冲突）
    let export_dir = find_available_export_dir(&target_path, &export_name);
    let data_dir = export_dir.join("data");
    let files_dir = export_dir.join("files");

    fs::create_dir_all(&export_dir).map_err(|err| format!("创建导出目录失败：{}", err))?;
    fs::create_dir_all(&data_dir).map_err(|err| format!("创建数据目录失败：{}", err))?;
    fs::create_dir_all(&files_dir).map_err(|err| format!("创建文件目录失败：{}", err))?;
    
    // 收集所有资源引用的文件路径
    let all_file_paths = collect_resource_file_paths(&selected_resources);
    
    // 复制文件并生成路径映射（去重）
    let path_mapping = copy_files_with_dedup(&all_file_paths, &files_dir)?;
    
    // 更新资源中的路径引用
    let processed_resources = update_resource_paths(&selected_resources, &path_mapping);
    
    // 转换为 Value 类型以便序列化
    let groups_value: Vec<serde_json::Value> = selected_groups
        .into_iter()
        .map(|g| serde_json::to_value(g).unwrap())
        .collect();
    
    let items_value: Vec<serde_json::Value> = processed_resources
        .into_iter()
        .map(|r| serde_json::to_value(r).unwrap())
        .collect();
    
    // 生成导出数据
    let export_data = ExportData {
        version: "1.0".to_string(),
        r#type: "custom".to_string(),
        export_name: export_name.clone(),
        groups: groups_value,
        items: items_value,
    };
    
    // 保存导出数据
    write_json(&data_dir.join("export.json"), &export_data)?;
    
    // 保存路径映射（如果有）
    if !path_mapping.is_empty() {
        write_json(&data_dir.join("path-mapping.json"), &path_mapping)?;
    }
    
    // 将导出文件夹打包为压缩文件（处理 ZIP 文件名冲突）
    let zip_path = find_available_zip_path(&target_path, &export_name);
    create_zip(&export_dir, &zip_path)?;

    // 打包完成后删除源文件夹
    fs::remove_dir_all(&export_dir)
        .map_err(|err| format!("删除源文件夹失败：{}", err))?;

    Ok(())
}


/// 将目录打包为 ZIP 文件
fn create_zip(source_dir: &PathBuf, output_path: &PathBuf) -> Result<(), String> {
    let file = fs::File::create(output_path)
        .map_err(|err| format!("创建压缩文件失败：{}", err))?;
    
    let mut zip = ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    
    // 遍历目录并添加所有文件
    for entry in WalkDir::new(source_dir) {
        let entry = entry.map_err(|err| format!("遍历目录失败：{}", err))?;
        let path = entry.path();
        
        // 获取相对路径
        let relative_path = path.strip_prefix(source_dir)
            .map_err(|err| format!("获取相对路径失败：{}", err))?;
        
        if path.is_file() {
            // 添加文件到压缩包
            zip.start_file_from_path(relative_path, options)
                .map_err(|err| format!("添加文件到压缩包失败：{}", err))?;
            
            let mut file_content = fs::read(path)
                .map_err(|err| format!("读取文件内容失败：{}", err))?;
            zip.write_all(&file_content)
                .map_err(|err| format!("写入压缩包失败：{}", err))?;
        } else if !relative_path.as_os_str().is_empty() {
            // 添加目录（如果非空）
            zip.add_directory_from_path(relative_path, options)
                .map_err(|err| format!("添加目录到压缩包失败：{}", err))?;
        }
    }
    
    zip.finish()
        .map_err(|err| format!("完成压缩失败：{}", err))?;
    
    Ok(())
}


// ==================== 解压工具函数 ====================

/// 查找包含 data/export.json 的目录
fn find_export_dir(base_path: &PathBuf) -> Option<PathBuf> {
    // 检查基础路径
    if base_path.join("data").join("export.json").exists() {
        return Some(base_path.clone());
    }
    
    // 检查一级子目录
    if let Ok(entries) = fs::read_dir(base_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // 检查这个子目录
                if path.join("data").join("export.json").exists() {
                    return Some(path);
                }
                
                // 检查二级子目录
                if let Ok(sub_entries) = fs::read_dir(&path) {
                    for sub_entry in sub_entries.flatten() {
                        let sub_path = sub_entry.path();
                        if sub_path.is_dir() && sub_path.join("data").join("export.json").exists() {
                            return Some(sub_path);
                        }
                    }
                }
            }
        }
    }
    
    None
}

#[tauri::command]
pub fn extract_zip_to_temp(zip_path: String) -> Result<String, String> {
    let zip_file = fs::File::open(&zip_path)
        .map_err(|err| format!("打开压缩文件失败：{}", err))?;
    
    // 创建临时目录
    let temp_dir = tempdir()
        .map_err(|err| format!("创建临时目录失败：{}", err))?;
    let temp_path = temp_dir.into_path(); 
    
    // 解压文件
    let mut archive = zip::ZipArchive::new(zip_file)
        .map_err(|err| format!("解析压缩文件失败：{}", err))?;
    
    archive.extract(&temp_path)
        .map_err(|err| format!("解压文件失败：{}", err))?;
    
    // 调试：打印解压后的目录结构
    print_dir_structure(&temp_path, 0);
    
    // 查找导出目录
    let export_dir = find_export_dir(&temp_path)
        .ok_or_else(|| "无法找到有效的导出目录：缺少 data/export.json".to_string())?;

    Ok(export_dir.to_string_lossy().to_string())
}

/// 递归打印目录结构（用于调试）
fn print_dir_structure(path: &Path, depth: usize) {
    let prefix = "  ".repeat(depth);
    
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let file_name = entry_path.file_name().unwrap_or_default().to_string_lossy();
        }
    }
}

/// 删除临时目录
#[tauri::command]
pub fn remove_temp_dir(temp_path: String) -> Result<(), String> {
    let path = PathBuf::from(temp_path);
    if path.exists() {
        fs::remove_dir_all(&path)
            .map_err(|err| format!("删除临时目录失败：{}", err))?;
    }
    Ok(())
}

/// 将解压的文件夹移动到软件路径的 external resources
#[tauri::command]
pub fn move_export_to_external(app: AppHandle, source_path: String) -> Result<String, String> {
    
    let source = PathBuf::from(source_path);

    // 获取应用数据目录（C:\Users\...\AppData\Roaming\com.hashcatgui.app）
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    
    // 创建 imported-presets 目录（与 task、hashes 同目录）
    let external_dir = app_data_dir.join("imported-presets");

    fs::create_dir_all(&external_dir)
        .map_err(|err| format!("创建外部资源目录失败：{}", err))?;
    
    // 从 export.json 读取原始导出名称
    let export_json_path = source.join("data").join("export.json");
    let dir_name = if export_json_path.exists() {
        if let Ok(content) = fs::read_to_string(&export_json_path) {
            if let Ok(export_data) = serde_json::from_str::<ExportData>(&content) {
                // 尝试从 groups 中获取第一个分组的完整ID
                if let Some(first_group) = export_data.groups.first() {
                    if let Some(group_id) = first_group.get("id").and_then(|v| v.as_str()) {
                        // 使用导出名称 + 第一个分组的完整ID作为文件夹名称
                        format!("{}_{}", export_data.export_name, group_id)
                    } else {
                        export_data.export_name
                    }
                } else {
                    export_data.export_name
                }
            } else {
                source.file_name().unwrap_or_default().to_string_lossy().to_string()
            }
        } else {
            source.file_name().unwrap_or_default().to_string_lossy().to_string()
        }
    } else {
        source.file_name().unwrap_or_default().to_string_lossy().to_string()
    };
    
    // 目标路径
    let target = external_dir.join(dir_name);
    
    // 如果目标已存在，删除它
    if target.exists() {
        fs::remove_dir_all(&target)
            .map_err(|err| format!("删除已存在的目标目录失败：{}", err))?;
    }
    

    // 如果目标已存在，删除它
    if target.exists() {
        fs::remove_dir_all(&target)
            .map_err(|err| format!("删除已存在的目标目录失败：{}", err))?;
    }

    // 使用 walkdir 递归复制目录
    for entry in WalkDir::new(&source).into_iter().filter_map(|e| e.ok()) {
        let target_path = target.join(entry.path().strip_prefix(&source).unwrap());
        
        if entry.path().is_dir() {
            fs::create_dir_all(&target_path)
                .map_err(|err| format!("创建目录失败：{}", err))?;
        } else {
            fs::copy(entry.path(), &target_path)
                .map_err(|err| format!("复制文件失败：{}", err))?;
        }
    }

    // 复制成功后删除原目录
    fs::remove_dir_all(&source)
        .map_err(|err| format!("删除原目录失败：{}", err))?;
    
    Ok(target.to_string_lossy().to_string())
}

// ==================== 导入功能 ====================

/// 读取导出元数据（用于预览）
#[tauri::command]
pub fn read_export_metadata(folder_path: String) -> Result<ImportPreviewData, String> {

    let mut folder = PathBuf::from(folder_path);

    // 尝试规范化路径（解决 Windows 短路径问题）
    if let Ok(canonical) = fs::canonicalize(&folder) {
        folder = canonical;
    }
    
    let export_json_path = folder.join("data").join("export.json");

    if !export_json_path.is_file() {
        return Err(format!("无效的导出文件夹：缺少 export.json\n路径: {}", export_json_path.to_string_lossy()).into());
    }
    
    let content = fs::read_to_string(&export_json_path)
        .map_err(|err| format!("读取 export.json 失败：{}", err))?;
    
    let export_data: ExportData = serde_json::from_str(&content)
        .map_err(|err| format!("解析 export.json 失败：{}", err))?;
    
    // 解析分组信息
    let mut groups: Vec<PreviewGroupInfo> = Vec::new();
    
    for group_value in &export_data.groups {
        let group_id = group_value.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let group_name = group_value.get("name").and_then(|v| v.as_str()).unwrap_or("");
        
        // 根据类型获取项目数量
        let item_count = if export_data.r#type == "preset" {
            // 尝试多种可能的字段名
            group_value.get("preset_ids").and_then(|v| v.as_array()).map(|arr| arr.len())
                .or_else(|| group_value.get("presetIds").and_then(|v| v.as_array()).map(|arr| arr.len()))
                .or_else(|| group_value.get("item_count").and_then(|v| v.as_u64()).map(|n| n as usize))
                .or_else(|| group_value.get("itemCount").and_then(|v| v.as_u64()).map(|n| n as usize))
                .unwrap_or(0)
        } else {
            group_value.get("resource_ids").and_then(|v| v.as_array()).map(|arr| arr.len())
                .or_else(|| group_value.get("resourceIds").and_then(|v| v.as_array()).map(|arr| arr.len()))
                .or_else(|| group_value.get("item_count").and_then(|v| v.as_u64()).map(|n| n as usize))
                .or_else(|| group_value.get("itemCount").and_then(|v| v.as_u64()).map(|n| n as usize))
                .unwrap_or(0)
        };
        
        groups.push(PreviewGroupInfo {
            id: group_id.to_string(),
            name: group_name.to_string(),
            item_count,
        });
    }
    
    Ok(ImportPreviewData {
        version: export_data.version,
        r#type: export_data.r#type,
        group_count: export_data.groups.len(),
        item_count: export_data.items.len(),
        groups,
    })
}


/// 导入预设
#[tauri::command]
pub fn import_presets(
    app: AppHandle,
    folder_path: String,
    import_mode: String,
) -> Result<ImportResult, String> {
    let folder = PathBuf::from(folder_path);
    let data_dir = folder.join("data");
    
    // 读取导出数据
    let export_json_path = data_dir.join("export.json");
    if !export_json_path.is_file() {
        return Err("无效的导出文件夹".into());
    }
    
    let content = fs::read_to_string(&export_json_path)
        .map_err(|err| format!("读取 export.json 失败：{}", err))?;
    
    let export_data: ExportData = serde_json::from_str(&content)
        .map_err(|err| format!("解析 export.json 失败：{}", err))?;
    
    if export_data.r#type != "preset" {
        return Err("导出数据类型不匹配：期望预设数据".into());
    }
    
    // 读取路径映射
    let path_mapping: HashMap<String, String> = {
        let mapping_path = data_dir.join("path-mapping.json");
        if mapping_path.is_file() {
            let mapping_content = fs::read_to_string(&mapping_path)
                .map_err(|err| format!("读取 path-mapping.json 失败：{}", err))?;
            serde_json::from_str(&mapping_content)
                .map_err(|err| format!("解析 path-mapping.json 失败：{}", err))?
        } else {
            HashMap::new()
        }
    };
    
    // 转换相对路径为绝对路径
    let absolute_mapping: HashMap<String, String> = path_mapping
        .into_iter()
        .map(|(_old, relative)| {
            let absolute = folder.join(&relative[2..]);
            let absolute_str = absolute.to_string_lossy().to_string();
            // 添加路径标准化
            let normalized = normalize_path(&absolute_str);
            (relative, normalized)
        })
        .collect();
    
    // 处理预设数据
    let mut processed_presets: Vec<PresetConfig> = Vec::new();
    for item_value in &export_data.items {
        let mut preset: PresetConfig = serde_json::from_value(item_value.clone())
            .map_err(|err| format!("解析预设数据失败：{}", err))?;
        
        // 更新路径引用
        update_preset_path_values(&mut preset, &absolute_mapping);
        
        processed_presets.push(preset);
    }
    
    // 处理分组数据
    let mut processed_groups: Vec<PresetGroup> = Vec::new();
    for group_value in &export_data.groups {
        let mut group: PresetGroup = serde_json::from_value(group_value.clone())
            .map_err(|err| format!("解析分组数据失败：{}", err))?;
        
        processed_groups.push(group);
    }
    
    // 保存到应用数据目录
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    fs::create_dir_all(&app_data_dir).map_err(|err| err.to_string())?;
    
    let presets_path = app_data_dir.join("presets.json");
    let groups_path = app_data_dir.join("preset_groups.json");
    
    // 读取现有数据
    let mut existing_presets: Vec<PresetConfig> = if presets_path.is_file() {
        let existing_content = fs::read_to_string(&presets_path).map_err(|err| err.to_string())?;
        serde_json::from_str(&existing_content).unwrap_or_default()
    } else {
        Vec::new()
    };
    
    let mut existing_groups: Vec<PresetGroup> = if groups_path.is_file() {
        let existing_content = fs::read_to_string(&groups_path).map_err(|err| err.to_string())?;
        serde_json::from_str(&existing_content).unwrap_or_default()
    } else {
        Vec::new()
    };
    
    // 先保存长度（在 extend 之前）
    let group_count = processed_groups.len();
    let preset_count = processed_presets.len();

    // 获取要导入的预设和分组ID
    let imported_preset_ids: HashSet<String> = processed_presets.iter().map(|p| p.id.clone()).collect();
    let imported_group_ids: HashSet<String> = processed_groups.iter().map(|g| g.id.clone()).collect();

    // 获取现有预设和分组ID（用于跳过模式）
    let existing_preset_ids: HashSet<String> = existing_presets.iter().map(|p| p.id.clone()).collect();
    let existing_group_ids: HashSet<String> = existing_groups.iter().map(|g| g.id.clone()).collect();

    match import_mode.as_str() {
        "overwrite" => {
            // 覆盖模式：删除现有数据中相同ID的项
            existing_presets.retain(|p| !imported_preset_ids.contains(&p.id));
            existing_groups.retain(|g| !imported_group_ids.contains(&g.id));
        }
        "skip" => {
            // 跳过模式：删除要导入数据中与现有ID冲突的项
            processed_presets.retain(|p| !existing_preset_ids.contains(&p.id));
            processed_groups.retain(|g| !existing_group_ids.contains(&g.id));
        }
        "merge" => {
            // 合并模式：只添加新增项，保留现有版本
            processed_presets.retain(|p| !existing_preset_ids.contains(&p.id));
            processed_groups.retain(|g| !existing_group_ids.contains(&g.id));
        }
        _ => {
            return Err(format!("无效的导入模式：{}", import_mode));
        }
    }

    // 合并数据
    existing_presets.extend(processed_presets);
    existing_groups.extend(processed_groups);

    // 保存
    write_json(&presets_path, &existing_presets)?;
    write_json(&groups_path, &existing_groups)?;

    // 导入成功后，删除 data 目录（配置已写入，不再需要）
    if data_dir.is_dir() {
        let _ = fs::remove_dir_all(&data_dir);
    }

    Ok(ImportResult {
        success: true,
        message: "导入成功".to_string(),
        imported_groups: group_count,
        imported_items: preset_count,
        conflicts: Vec::new(),
    })
}

/// 导人自定义资源
#[tauri::command]
pub fn import_resources(
    app: AppHandle,
    folder_path: String,
    import_mode: Option<String>,
) -> Result<ImportResult, String> {
    let folder = PathBuf::from(folder_path);
    let data_dir = folder.join("data");
    
    // 读取导出数据
    let export_json_path = data_dir.join("export.json");
    if !export_json_path.is_file() {
        return Err("无效的导出文件夹".into());
    }
    
    let content = fs::read_to_string(&export_json_path)
        .map_err(|err| format!("读取 export.json 失败：{}", err))?;
    
    let export_data: ExportData = serde_json::from_str(&content)
        .map_err(|err| format!("解析 export.json 失败：{}", err))?;
    
    if export_data.r#type != "custom" {
        return Err("导出数据类型不匹配：期望自定义资源数据".into());
    }
    
    // 读取路径映射
    let path_mapping: HashMap<String, String> = {
        let mapping_path = data_dir.join("path-mapping.json");
        if mapping_path.is_file() {
            let mapping_content = fs::read_to_string(&mapping_path)
                .map_err(|err| format!("读取 path-mapping.json 失败：{}", err))?;
            serde_json::from_str(&mapping_content)
                .map_err(|err| format!("解析 path-mapping.json 失败：{}", err))?
        } else {
            HashMap::new()
        }
    };
    
    // 转换相对路径为绝对路径
    let absolute_mapping: HashMap<String, String> = path_mapping
        .into_iter()
        .map(|(_old, relative)| {
            let absolute = folder.join(&relative[2..]);
            let absolute_str = absolute.to_string_lossy().to_string();
            // 添加路径标准化
            let normalized = normalize_path(&absolute_str);
            (relative, normalized)
        })
        .collect();
    
    // 处理资源数据
    let mut processed_resources: Vec<CustomResource> = Vec::new();
    for item_value in &export_data.items {
        let mut resource: CustomResource = serde_json::from_value(item_value.clone())
            .map_err(|err| format!("解析资源数据失败：{}", err))?;

        update_resource_path_values(&mut resource, &absolute_mapping);
        processed_resources.push(resource);
    }
    
    // 处理分组数据
    let mut processed_groups: Vec<ResourceGroup> = Vec::new();
    for group_value in &export_data.groups {
        let mut group: ResourceGroup = serde_json::from_value(group_value.clone())
            .map_err(|err| format!("解析分组数据失败：{}", err))?;

        processed_groups.push(group);
    }
    
    // 保存到应用数据目录
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    fs::create_dir_all(&app_data_dir).map_err(|err| err.to_string())?;
    
    let resources_path = app_data_dir.join("custom_resources.json");
    let groups_path = app_data_dir.join("resource_groups.json");
    
    // 读取现有数据
    let mut existing_resources: Vec<CustomResource> = if resources_path.is_file() {
        let existing_content = fs::read_to_string(&resources_path).map_err(|err| err.to_string())?;
        serde_json::from_str(&existing_content).unwrap_or_default()
    } else {
        Vec::new()
    };
    
    let mut existing_groups: Vec<ResourceGroup> = if groups_path.is_file() {
        let existing_content = fs::read_to_string(&groups_path).map_err(|err| err.to_string())?;
        serde_json::from_str(&existing_content).unwrap_or_default()
    } else {
        Vec::new()
    };
    
    // 先保存长度（在 extend 之前）
    let group_count = processed_groups.len();
    let resource_count = processed_resources.len();

    // 获取要导入的资源和分组ID
    let _imported_resource_ids: HashSet<String> = processed_resources.iter().map(|r| r.id.clone()).collect();
    let _imported_group_ids: HashSet<String> = processed_groups.iter().map(|g| g.id.clone()).collect();

    // 根据导入模式处理冲突
    let mode = import_mode.unwrap_or_else(|| "merge".to_string());
    let existing_resource_ids: HashSet<String> = existing_resources.iter().map(|r| r.id.clone()).collect();
    let existing_group_ids: HashSet<String> = existing_groups.iter().map(|g| g.id.clone()).collect();

    match mode.as_str() {
        "skip" => {
            // 跳过冲突项
            processed_resources.retain(|r| !existing_resource_ids.contains(&r.id));
            processed_groups.retain(|g| !existing_group_ids.contains(&g.id));
        }
        "overwrite" => {
            // 覆盖模式：移除已存在的项
            existing_resources.retain(|r| !processed_resources.iter().any(|pr| pr.id == r.id));
            existing_groups.retain(|g| !processed_groups.iter().any(|pg| pg.id == g.id));
        }
        "merge" | _ => {
            // 合并模式：只添加新增项
            processed_resources.retain(|r| !existing_resource_ids.contains(&r.id));
            processed_groups.retain(|g| !existing_group_ids.contains(&g.id));
        }
    }

    // 合并数据
    existing_resources.extend(processed_resources);
    existing_groups.extend(processed_groups);

    // 保存
    write_json(&resources_path, &existing_resources)?;
    write_json(&groups_path, &existing_groups)?;

    // 导入成功后，删除 data 目录（配置已写入，不再需要）
    if data_dir.is_dir() {
        let _ = fs::remove_dir_all(&data_dir);
    }
    
    Ok(ImportResult {
        success: true,
        message: "导入成功".to_string(),
        imported_groups: group_count,
        imported_items: resource_count,
        conflicts: Vec::new(),
    })
}

// ==================== 辅助函数 ====================

/// 收集预设引用的所有文件路径
fn collect_preset_file_paths(presets: &[PresetConfig]) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    
    for preset in presets {
        if let Some(path) = &preset.dictionary_path {
            if !path.is_empty() {
                paths.push(path.clone());
            }
        }
        if let Some(path) = &preset.dictionary_path2 {
            if !path.is_empty() {
                paths.push(path.clone());
            }
        }
        paths.extend(preset.dictionary_paths.iter().filter(|p| !p.is_empty()).cloned());
        
        if let Some(path) = &preset.mask_path {
            if !path.is_empty() {
                paths.push(path.clone());
            }
        }
        
        // 处理规则路径（规则可能以 @ 开头表示文件路径）
        if let Some(rule) = &preset.left_rule {
            if let Some(path) = rule.strip_prefix('@') {
                if !path.is_empty() {
                    paths.push(path.to_string());
                }
            }
        }
        if let Some(rule) = &preset.right_rule {
            if let Some(path) = rule.strip_prefix('@') {
                if !path.is_empty() {
                    paths.push(path.to_string());
                }
            }
        }
        paths.extend(preset.rule_paths.iter().filter(|p| !p.is_empty()).cloned());
    }
    
    paths
}

/// 收集自定义资源引用的所有文件路径
fn collect_resource_file_paths(resources: &[CustomResource]) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    
    for resource in resources {
        if let Some(path) = &resource.path {
            if !path.is_empty() && PathBuf::from(path).is_file() {
                paths.push(path.clone());
            }
        }
    }
    
    paths
}

/// 计算文件的MD5哈希值
fn compute_file_md5(file_path: &Path) -> Result<String, String> {
    let file = fs::File::open(file_path)
        .map_err(|err| format!("打开文件失败 {}: {}", file_path.display(), err))?;
    let mut reader = BufReader::new(file);
    let mut context = md5::Context::new();
    let mut buffer = [0u8; 8192];
    
    loop {
        let bytes_read = reader.read(&mut buffer)
            .map_err(|err| format!("读取文件失败 {}: {}", file_path.display(), err))?;
        if bytes_read == 0 {
            break;
        }
        context.consume(&buffer[..bytes_read]);
    }
    
    Ok(format!("{:x}", context.compute()))
}

/// 复制文件并去重，返回路径映射
/// 去重策略：
/// 1. 相同MD5的文件只导出一份（内容相同但路径不同）
/// 2. 文件名冲突时自动重命名
fn copy_files_with_dedup(source_paths: &[String], dest_dir: &Path) -> Result<HashMap<String, String>, String> {
    let mut path_mapping: HashMap<String, String> = HashMap::new();
    let mut exported_files: HashSet<String> = HashSet::new(); // 记录已导出的源路径
    let mut md5_to_path: HashMap<String, String> = HashMap::new(); // 记录MD5到导出路径的映射
    
    for source_path in source_paths {
        // 跳过已导出的文件（相同路径）
        if exported_files.contains(source_path) {
            continue;
        }
        
        let source = PathBuf::from(source_path);
        
        // 跳过不存在的文件
        if !source.is_file() {
            continue;
        }
        
        // 计算文件MD5哈希值
        let md5 = match compute_file_md5(&source) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("计算文件MD5失败 {}: {}", source_path, e);
                continue;
            }
        };
        
        // 检查是否已有相同MD5的文件被导出
        if let Some(existing_path) = md5_to_path.get(&md5) {
            // 复用已导出的文件路径
            path_mapping.insert(source_path.clone(), existing_path.clone());
            exported_files.insert(source_path.clone());
            continue;
        }
        
        let file_name = source.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        // 处理文件名冲突
        let mut dest_name = file_name.clone();
        let mut counter = 1;
        
        while dest_dir.join(&dest_name).exists() {
            let ext = PathBuf::from(&file_name).extension()
                .map(|e| e.to_string_lossy().to_string());
            let stem = PathBuf::from(&file_name).file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or(file_name.clone());
            
            dest_name = if let Some(ext) = ext {
                format!("{}_{}.{}", stem, counter, ext)
            } else {
                format!("{}_{}", stem, counter)
            };
            counter += 1;
        }
        
        let dest = dest_dir.join(&dest_name);
        
        // 复制文件
        fs::copy(&source, &dest)
            .map_err(|err| format!("复制文件失败 {} -> {}: {}", source.display(), dest.display(), err))?;
        
        // 记录已导出
        exported_files.insert(source_path.clone());
        
        // 记录MD5映射
        let relative_path = format!("./files/{}", dest_name);
        md5_to_path.insert(md5, relative_path.clone());
        
        // 记录路径映射（相对路径）
        path_mapping.insert(source_path.clone(), relative_path);
    }
    
    Ok(path_mapping)
}

/// 更新预设中的路径引用（相对路径）
fn update_preset_paths(presets: &[PresetConfig], path_mapping: &HashMap<String, String>) -> Vec<PresetConfig> {
    presets.iter().map(|preset| {
        let mut updated = preset.clone();
        update_preset_path_values(&mut updated, path_mapping);
        updated
    }).collect()
}

/// 更新资源中的路径引用（相对路径）
fn update_resource_paths(resources: &[CustomResource], path_mapping: &HashMap<String, String>) -> Vec<CustomResource> {
    resources.iter().map(|resource| {
        let mut updated = resource.clone();
        update_resource_path_values(&mut updated, path_mapping);
        updated
    }).collect()
}

/// 更新预设的路径值
fn update_preset_path_values(preset: &mut PresetConfig, mapping: &HashMap<String, String>) {
    if let Some(path) = &preset.dictionary_path {
        if let Some(new_path) = mapping.get(path) {
            preset.dictionary_path = Some(new_path.clone());
        }
    }
    if let Some(path) = &preset.dictionary_path2 {
        if let Some(new_path) = mapping.get(path) {
            preset.dictionary_path2 = Some(new_path.clone());
        }
    }
    preset.dictionary_paths = preset.dictionary_paths.iter()
        .map(|p| mapping.get(p).cloned().unwrap_or(p.clone()))
        .collect();
    
    if let Some(path) = &preset.mask_path {
        if let Some(new_path) = mapping.get(path) {
            preset.mask_path = Some(new_path.clone());
        }
    }
    
    if let Some(rule) = &preset.left_rule {
        if let Some(path) = rule.strip_prefix('@') {
            if let Some(new_path) = mapping.get(path) {
                preset.left_rule = Some(format!("@{}", new_path));
            }
        }
    }
    if let Some(rule) = &preset.right_rule {
        if let Some(path) = rule.strip_prefix('@') {
            if let Some(new_path) = mapping.get(path) {
                preset.right_rule = Some(format!("@{}", new_path));
            }
        }
    }
    preset.rule_paths = preset.rule_paths.iter()
        .map(|p| mapping.get(p).cloned().unwrap_or(p.clone()))
        .collect();
}

/// 更新资源的路径值
fn update_resource_path_values(resource: &mut CustomResource, mapping: &HashMap<String, String>) {
    if let Some(path) = &resource.path {
        if let Some(new_path) = mapping.get(path) {
            resource.path = Some(new_path.clone());
        }
    }
}

/// 写入 JSON 文件
fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let text = serde_json::to_string_pretty(value).map_err(|err| err.to_string())?;
    fs::write(path, text).map_err(|err| err.to_string())
}


// ==================== 预设数据 ====================

#[tauri::command]
pub fn read_presets_file(app: AppHandle) -> Result<String, String> {
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    let presets_path = app_data_dir.join("presets.json");
    
    if presets_path.is_file() {
        fs::read_to_string(&presets_path).map_err(|err| err.to_string())
    } else {
        Ok("[]".to_string())
    }
}

#[tauri::command]
pub fn write_presets_file(app: AppHandle, presets_json: String, allow_empty: Option<bool>) -> Result<(), String> {
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    fs::create_dir_all(&app_data_dir).map_err(|err| err.to_string())?;
    
    let presets_path = app_data_dir.join("presets.json");
    
    let is_empty_array = presets_json.trim() == "[]";
    if is_empty_array && !allow_empty.unwrap_or(false) {
        // 如果文件已存在且不允许清空，则拒绝写入
        if presets_path.is_file() {
            return Err("不允许意外清空预设数据。如需清空，请使用管理模式或设置 allow_empty=true".to_string());
        }
        // 文件不存在时允许写入空数组（初始化场景）
    }
    
    fs::write(&presets_path, presets_json).map_err(|err| err.to_string())
}

#[tauri::command]
pub fn read_preset_groups_file(app: AppHandle) -> Result<String, String> {
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    let groups_path = app_data_dir.join("preset_groups.json");
    
    if groups_path.is_file() {
        fs::read_to_string(&groups_path).map_err(|err| err.to_string())
    } else {
        Ok("[]".to_string())
    }
}

#[tauri::command]
pub fn write_preset_groups_file(app: AppHandle, groups_json: String) -> Result<(), String> {
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    fs::create_dir_all(&app_data_dir).map_err(|err| err.to_string())?;
    
    let groups_path = app_data_dir.join("preset_groups.json");
    fs::write(&groups_path, groups_json).map_err(|err| err.to_string())
}

// ==================== 自定义资源数据 ====================

#[tauri::command]
pub fn read_custom_resources_file(app: AppHandle) -> Result<String, String> {
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    let resources_path = app_data_dir.join("custom_resources.json");
    
    if resources_path.is_file() {
        fs::read_to_string(&resources_path).map_err(|err| err.to_string())
    } else {
        Ok("[]".to_string())
    }
}

#[tauri::command]
pub fn write_custom_resources_file(app: AppHandle, resources_json: String) -> Result<(), String> {
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    fs::create_dir_all(&app_data_dir).map_err(|err| err.to_string())?;
    
    let resources_path = app_data_dir.join("custom_resources.json");
    fs::write(&resources_path, resources_json).map_err(|err| err.to_string())
}

#[tauri::command]
pub fn read_resource_groups_file(app: AppHandle) -> Result<String, String> {
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    let groups_path = app_data_dir.join("resource_groups.json");
    
    if groups_path.is_file() {
        fs::read_to_string(&groups_path).map_err(|err| err.to_string())
    } else {
        Ok("[]".to_string())
    }
}

#[tauri::command]
pub fn write_resource_groups_file(app: AppHandle, groups_json: String) -> Result<(), String> {
    let app_data_dir = app.path().app_data_dir()
        .map_err(|err| format!("获取应用数据目录失败：{}", err))?;
    fs::create_dir_all(&app_data_dir).map_err(|err| err.to_string())?;
    
    let groups_path = app_data_dir.join("resource_groups.json");
    fs::write(&groups_path, groups_json).map_err(|err| err.to_string())
}