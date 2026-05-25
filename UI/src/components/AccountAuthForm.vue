<script setup>
    import { computed, ref,h } from 'vue';
    import { InfoFilled, WarnTriangleFilled  } from '@element-plus/icons-vue';
    import { ElMessageBox, ElMessage, ElSwitch } from 'element-plus';

    /**
     * 属性定义
     * modelValue: 用于 v-model 绑定
     * customTips: 外部传入的自定义提示语
     */
    const props = defineProps({
        modelValue: {
            type: Object,
            required: true
        },
        customTips: {
            type: String,
            default: ''
        },
        small: {
            type: Boolean,
            default: false
        }
    });

    // 是否跳过提示框
    const skipModifyTip = ref(localStorage.getItem("skipModifyTip") ? true : false);
    let firstUsernameFocus = false;
    // 缓存旧的值
    const originalAccountType = ref(props.modelValue.accountType);
    const originalUsername = ref(props.modelValue.username);

    const showModifyWarning = (field) => {
        // 如果已勾选跳过提示
        if (skipModifyTip.value) return;

        const checked = ref(false);
        ElMessageBox.confirm('', '',{
            title: '修改警告',
            message: () => h('div', null, [
                h('p', null, [
                    h('span', null, '账户类型和用户名是自动识别的， '),
                    h('b', { style: 'color: red' }, '一般情况下无需修改。'),
                    h('br', null, ''),
                    h('span', null, '除非你完全清楚修改此信息的后果并确认需要调整，否则请保持默认值。 '),
                ]),
                h('div', { style: 'display: flex; align-items:center; margin-top: 15px;' }, [
                    h('p', { style: 'margin-right: 10px;' }, '不再提醒 '),
                    h(ElSwitch, {
                        modelValue: checked.value,
                        'onUpdate:modelValue': (val) => {
                            checked.value = val;
                            skipModifyTip.value = val;
                            if(val){
                                localStorage.setItem("skipModifyTip", '1');
                            } else {
                                localStorage.removeItem("skipModifyTip");
                            }
                        },
                    }),
                ])
            ]),
            confirmButtonText: '我明确要修改',
            cancelButtonText: '取消修改',
            type: 'warning'
        }).then(() => {}).catch(() => {
            if (field === 'accountType') {
                formData.value.accountType = originalAccountType.value;
            } else if (field === 'username') {
                formData.value.username = originalUsername.value;
            }
        });
    };

    const emit = defineEmits(['update:modelValue']);

    // 使用计算属性来简化 v-model 的绑定逻辑
    const formData = computed({
        get: () => props.modelValue,
        set: (val) => emit('update:modelValue', val)
    });

    const handleBlur = (field) => {
        if(field === "username"){
            if(formData.value.username != originalUsername.value) {
                showModifyWarning(field);
            }
        }
    }

    const handleFocus = ()=>{
        if(!firstUsernameFocus){
            firstUsernameFocus = true;
            // 更新原用户名的值，因为是从Rust获取的
            originalUsername.value = formData.value.username;
        }
    }

    const defaultTips = '此凭据将用于 DLL 调起 WinLogon 认证，不会上传至任何云端。';
</script>

<template>
    <div class="account-auth-container">
        <el-form :model="formData" label-position="top" class="auth-form">
            <el-form-item label="账户类型">
                <el-select
                    v-model = "formData.accountType"
                    @focus="handleFocus"
                    @change="showModifyWarning('accountType')"
                    placeholder="请选择账户类型"
                    style="width: 100%"
                >
                    <el-option label="本地账户 (Local Account)" value="local" />
                    <el-option label="联机账户 (Microsoft Account)" value="online" />
                    <el-option label="域账户 (Domain Account)" value="domain" />
                </el-select>
            </el-form-item>

            <!-- 域账户：域名输入 -->
            <el-form-item v-if="formData.accountType === 'domain'" label="域名称">
                <el-input v-model="formData.domain" placeholder="例如: CORP">
                    <template #prefix>
                        <span style="padding-left: 5px; color: #409EFF; font-weight: bold;">\</span>
                    </template>
                </el-input>
            </el-form-item>

            <el-form-item :label="formData.accountType === 'local' ? 'Windows 用户名' : formData.accountType === 'domain' ? '域用户名' : '微软账号 Email'">
                <el-input v-model="formData.username" :placeholder="formData.accountType === 'local' ? '例如: Administrator' : formData.accountType === 'domain' ? '例如: jdoe' : '例如: user@outlook.com'" @focus="handleFocus" @blur="handleBlur('username')">
                    <template v-if="formData.accountType === 'local' || formData.accountType === 'domain'" #prefix>
                        <span style="padding-left: 5px; color: #409EFF; font-weight: bold;">{{ formData.accountType === 'domain' && formData.domain ? formData.domain + '\\' : '.\\' }}</span>
                    </template>
                </el-input>
            </el-form-item>

            <el-form-item label="系统登录密码">
                <template #label>
                    <div class="label-box">
                        <span>系统登录密码</span>
                        <el-tooltip
                            v-if="small"
                            :content="`<span>${customTips || defaultTips}</span>`"
                            placement="top-end"
                            raw-content
                        >
                            <el-icon class="question-icon"><WarnTriangleFilled /></el-icon>
                        </el-tooltip>
                    </div>
                </template>
                <el-input v-model="formData.password" type="password" show-password placeholder="请输入对应的登录密码" />
            </el-form-item>

            <div class="auth-tips" v-if="!small">
                <el-icon>
                    <InfoFilled />
                </el-icon>
                <span v-html="customTips || defaultTips"></span>
            </div>
        </el-form>
    </div>
</template>

<style scoped>
    .account-auth-container {
        width: 100%;
    }

    .auth-form :deep(.el-form-item__label) {
        font-weight: 600;
        padding-bottom: 4px;
    }

    .auth-tips {
        margin-top: 15px;
        padding: 12px;
        background-color: #f4f4f5;
        border-left: 4px solid #909399;
        border-radius: 4px;
        font-size: 12px;
        color: #606266;
        display: flex;
        align-items: flex-start;
        gap: 8px;
        line-height: 1.6;
        margin-bottom: 15px;
    }

    .auth-tips .el-icon {
        margin-top: 2px;
        flex-shrink: 0;
    }

    .label-box{
        display: flex;
        align-items: center;
    }

    .question-icon{
        font-size: 18px;
        margin-left: 5px;
        cursor: pointer;
    }
</style>