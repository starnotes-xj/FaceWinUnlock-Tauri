<script setup lang="ts">
import { ref, computed } from 'vue';
import { ElMessageBox, ElMessage } from 'element-plus';
import { User, Avatar } from '@element-plus/icons-vue';
import { useRouter } from 'vue-router';
import { useFacesStore } from '../../stores/faces';
import { storeToRefs } from 'pinia';

const router = useRouter();
const facesStore = useFacesStore();

const searchQuery = ref('');
const { faceList } = storeToRefs(facesStore);
const filteredList = computed(() => {
  return faceList.value.filter(item => {
    if (item.json_data.alias) {
      return item.json_data.alias.includes(searchQuery.value) || item.user_name.includes(searchQuery.value);
    } else {
      return item.user_name.includes(searchQuery.value);
    }
  });
});

const handleView = (face: any) => {
  facesStore.editFaceJsonData(JSON.stringify({ ...face.json_data, view: !(face.json_data.view) }), face.id).catch((error: any) => {
    ElMessage.warning(error);
  });
};

const handleLock = (face: any) => {
  facesStore.editFaceJsonData(JSON.stringify({ ...face.json_data, lock: !(face.json_data.lock) }), face.id).then(() => {
    if (face.json_data.lock) { ElMessage.success('禁用面容成功'); }
    else { ElMessage.success('启用面容成功'); }
  }).catch((error: any) => { ElMessage.warning(error); });
};

const accountTypeLabel = (type: string) => {
  if (type === 'online') return '联机';
  if (type === 'domain') return '域账户';
  return '本地';
};

const accountTypeTag = (type: string): 'primary' | 'success' | 'info' => {
  if (type === 'online') return 'primary';
  if (type === 'domain') return 'success';
  return 'info';
};

const handleEdit = (face: any) => {
  router.push({ path: '/faces/add', query: { id: face.id, mode: 'edit' } });
};

const confirmDelete = (face: any) => {
  ElMessageBox.confirm(
    `确定要删除面容 [${face.json_data.alias || face.user_name}] 吗？删除后将无法使用该面容解锁系统。`,
    '警告', { confirmButtonText: '确定删除', cancelButtonText: '取消', type: 'warning' }
  ).then(() => {
    facesStore.deleteFace(face.id).then(() => { ElMessage.success('删除成功'); })
      .catch((error: any) => { ElMessage.warning(error); });
  });
};
</script>

<template>
  <div class="face-list-container">
    <!-- Header -->
    <div class="list-header">
      <div class="header-info">
        <span class="total-text">已注册面容: <strong>{{ faceList.length }}</strong> / 无限</span>
      </div>
      <div class="header-actions">
        <el-input v-model="searchQuery" placeholder="搜索备注或用户名..." style="width: 250px; margin-right: 15px"
          prefix-icon="Search" clearable />
        <el-button type="primary" icon="Plus" @click="$router.push('/faces/add')">添加新面容</el-button>
      </div>
    </div>

    <!-- Face Grid -->
    <el-scrollbar v-if="filteredList.length > 0">
      <el-row :gutter="20" style="width: 100%;">
        <el-col v-for="face in filteredList" :key="face.id" :xs="24" :sm="12" :md="8" :lg="6">
          <div class="v7-card face-card" :class="{ 'disabled': face.json_data.lock }">
            <!-- Face Preview -->
            <div class="face-preview">
              <div class="disabled-overlay" v-if="face.json_data.lock">
                <div class="disabled-label">已禁用</div>
              </div>
              <div class="face-img-wrapper">
                <img v-face-img="face" class="face-img">
                <div class="image-slot">
                  <el-icon :size="48"><Avatar /></el-icon>
                </div>
              </div>
              <!-- Hover Actions -->
              <div class="card-overlay">
                <el-button size="small" circle :icon="face.json_data.lock ? 'Unlock' : 'Lock'"
                  @click="handleLock(face)" :title="face.json_data.lock ? '启用面容' : '禁用面容'"/>
                <el-button size="small" circle :icon="face.json_data.view ? 'Hide' : 'View'"
                  @click="handleView(face)" :title="face.json_data.view ? '隐藏缩略图' : '显示缩略图'"/>
                <el-button size="small" circle icon="Edit" @click="handleEdit(face)" title="编辑面容"/>
              </div>
            </div>

            <!-- Info -->
            <div class="face-info">
              <div class="info-row main">
                <span class="alias">{{ face.json_data.alias ? face.json_data.alias : '无别名' }}</span>
                <el-tag size="small" :type="accountTypeTag(face.account_type)">
                  {{ accountTypeLabel(face.account_type) }}
                </el-tag>
              </div>
              <div class="info-row sub">
                <el-icon :size="14"><User /></el-icon>
                <span>{{ face.user_name }}</span>
              </div>
              <div class="info-row time">
                <span>注册于: {{ face.createTime }}</span>
              </div>
              <div class="card-footer">
                <el-button type="danger" plain icon="Delete" size="small" @click="confirmDelete(face)">删除</el-button>
              </div>
            </div>
          </div>
        </el-col>
      </el-row>
    </el-scrollbar>

    <!-- Empty State -->
    <el-empty v-else description="暂无面容数据，请先添加" :image-size="200">
      <el-button type="primary" size="large" @click="$router.push('/faces/add')">立即录入面容</el-button>
    </el-empty>
  </div>
</template>

<style scoped>
.list-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  background: linear-gradient(135deg, rgba(201,166,62,.08), transparent 45%), var(--v7-surface-card);
  padding: 16px 22px;
  border-radius: 18px;
  border: 1px solid var(--v7-border-subtle);
  box-shadow: 0 24px 64px -44px rgba(0,0,0,.6), var(--v7-shadow);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
}

.header-actions { display: flex; align-items: center; }

.total-text { color: var(--v7-text-secondary); font-size: 14px; }
.total-text strong { color: var(--v7-gold-bright); font-size: 1.2em; }

/* ====== Face Cards ====== */
.face-card {
  margin-bottom: 20px;
  padding: 0 !important;
  border-radius: 18px !important;
  overflow: hidden;
}

.face-card.disabled {
  opacity: .7;
  border-color: rgba(194,53,49,.2) !important;
}

.face-preview {
  height: 160px;
  background: var(--v7-ink-deep);
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}

.face-img-wrapper {
  width: 100%; height: 100%;
  position: relative; overflow: hidden;
  display: flex; align-items: center; justify-content: center;
}

.face-img {
  max-width: 100%; max-height: 100%;
  object-fit: contain;
  position: absolute; inset: 0; margin: auto;
  display: none;
}
.face-img[src] { display: block; }

.image-slot {
  width: 100%; height: 100%;
  display: flex; align-items: center; justify-content: center;
  color: var(--v7-text-dim); font-size: 48px;
  position: absolute; inset: 0;
}
.face-img[src] + .image-slot { display: none; }

/* Disabled overlay */
.disabled-overlay {
  position: absolute; inset: 0;
  background: rgba(194,53,49,.12);
  display: flex; align-items: center; justify-content: center;
  z-index: 10; pointer-events: none;
}
.disabled-label {
  background: var(--v7-cinnabar); color: var(--v7-gold-pale);
  padding: 4px 12px; border-radius: 6px;
  border: 1px solid rgba(201,166,62,.28);
  font-size: 14px; font-weight: bold;
  transform: rotate(-15deg);
  box-shadow: 0 2px 8px rgba(194,53,49,.4);
}

/* Hover actions */
.card-overlay {
  position: absolute; bottom: 0; width: 100%;
  height: 42px;
  background: rgba(0,0,0,.6);
  display: flex; align-items: center; justify-content: flex-end;
  padding: 0 10px;
  opacity: 0; transition: opacity .3s;
  z-index: 20;
  gap: 6px;
}
.face-card:hover .card-overlay { opacity: 1; }

/* Info */
.face-info { padding: 15px; }

.info-row {
  display: flex; align-items: center; gap: 8px;
  margin-bottom: 8px; font-size: 13px;
  color: var(--v7-text-secondary);
}
.info-row.main { justify-content: space-between; }
.alias { font-weight: bold; font-size: 15px; color: var(--v7-text-primary); }

.card-footer {
  margin-top: 12px; padding-top: 10px;
  border-top: 1px dashed var(--v7-border-subtle);
  display: flex; justify-content: flex-end;
}

.face-card.disabled .alias { color: var(--v7-text-dim); text-decoration: line-through; }
</style>
