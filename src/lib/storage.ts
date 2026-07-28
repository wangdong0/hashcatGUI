// src/lib/storage.ts
import { invoke } from '@tauri-apps/api/core';

// 预设相关存储
export const presetStorage = {
  async getPresets(): Promise<string> {
    return invoke('read_presets_file');
  },
  
  async setPresets(json: string, allowEmpty: boolean = false): Promise<void> {
    return invoke('write_presets_file', { presetsJson: json, allowEmpty });
  },
  
  async getPresetGroups(): Promise<string> {
    return invoke('read_preset_groups_file');
  },
  
  async setPresetGroups(json: string): Promise<void> {
    return invoke('write_preset_groups_file', { groupsJson: json });
  },
};

// 自定义资源相关存储
export const resourceStorage = {
  async getCustomResources(): Promise<string> {
    return invoke('read_custom_resources_file');
  },
  
  async setCustomResources(json: string): Promise<void> {
    return invoke('write_custom_resources_file', { resourcesJson: json });
  },
  
  async getResourceGroups(): Promise<string> {
    return invoke('read_resource_groups_file');
  },
  
  async setResourceGroups(json: string): Promise<void> {
    return invoke('write_resource_groups_file', { groupsJson: json });
  },
};

// 数据迁移：从 localStorage 迁移到后端文件
export async function migrateFromLocalStorage(): Promise<void> {
  // 迁移预设
  const presetsFromStorage = localStorage.getItem('hashcatgui-presets');
  if (presetsFromStorage && presetsFromStorage !== '[]') {
    try {
      await presetStorage.setPresets(presetsFromStorage);
      localStorage.removeItem('hashcatgui-presets');
    } catch (e) {
      console.warn('Failed to migrate presets:', e);
    }
  }
  
  // 迁移预设分组
  const presetGroupsFromStorage = localStorage.getItem('hashcatgui-preset-groups');
  if (presetGroupsFromStorage && presetGroupsFromStorage !== '[]') {
    try {
      await presetStorage.setPresetGroups(presetGroupsFromStorage);
      localStorage.removeItem('hashcatgui-preset-groups');
    } catch (e) {
      console.warn('Failed to migrate preset groups:', e);
    }
  }
  
  // 迁移自定义资源
  const customResourcesFromStorage = localStorage.getItem('hashcatgui-custom-resources');
  if (customResourcesFromStorage && customResourcesFromStorage !== '[]') {
    try {
      await resourceStorage.setCustomResources(customResourcesFromStorage);
      localStorage.removeItem('hashcatgui-custom-resources');
    } catch (e) {
      console.warn('Failed to migrate custom resources:', e);
    }
  }
  
  // 迁移资源分组
  const resourceGroupsFromStorage = localStorage.getItem('hashcatgui-resource-groups');
  if (resourceGroupsFromStorage && resourceGroupsFromStorage !== '[]') {
    try {
      await resourceStorage.setResourceGroups(resourceGroupsFromStorage);
      localStorage.removeItem('hashcatgui-resource-groups');
    } catch (e) {
      console.warn('Failed to migrate resource groups:', e);
    }
  }
}