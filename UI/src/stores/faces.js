import { defineStore } from 'pinia';
import { invoke } from '@tauri-apps/api/core';
import { select, insert, update, deleteData } from '../utils/sqlite';
import { formatObjectString, getCurrentDateTime, removeFace } from '../utils/function';
import { error as errorLog, warn } from '@tauri-apps/plugin-log';

export const useFacesStore = defineStore('faces', {
    actions: {
        async init() {
            try {
                const result = await select('faces', [
                    'id', 'user_name', 'account_type', 'face_token', 'json_data', 'createTime'
                ]);
                this.faceList = result.rows.map((item) => ({
                    id: item.id,
                    user_name: item.user_name,
                    account_type: item.account_type,
                    face_token: item.face_token,
                    json_data: JSON.parse(item.json_data),
                    createTime: item.createTime
                }));
            } catch (error) {
                errorLog(formatObjectString('初始化Store失败：', error));
                throw error;
            }
        },

        async addFace(data) {
            try {
                const protectedPassword = await invoke('protect_credential', { password: data.user_pwd });
                const result = await insert(
                    'faces',
                    ['user_name', 'user_pwd', 'account_type', 'face_token', 'json_data'],
                    [data.user_name, protectedPassword, data.account_type, data.face_token, data.json_data]
                );
                this.addFaceToList({
                    id: result.lastId,
                    createTime: getCurrentDateTime(),
                    ...data
                });
            } catch (error) {
                errorLog(formatObjectString('添加数据到数据库失败：', error));
                throw error;
            }
        },

        async editFace(data, id) {
            const faceIndex = this.faceList.findIndex(item => item.id == id);
            if (faceIndex === -1) {
                const message = `未找到id: ${id} 的面容信息`;
                warn(message);
                throw message;
            }

            try {
                const changes = {
                    user_name: data.user_name,
                    account_type: data.account_type,
                    face_token: data.face_token,
                    json_data: data.json_data
                };
                if (data.update_password) {
                    changes.user_pwd = await invoke('protect_credential', { password: data.user_pwd });
                }
                await update('faces', changes, 'id = ?', [id]);
                this.faceList[faceIndex].json_data = JSON.parse(data.json_data);
                this.faceList[faceIndex].user_name = data.user_name;
                this.faceList[faceIndex].account_type = data.account_type;
                this.faceList[faceIndex].face_token = data.face_token;
            } catch (error) {
                errorLog(formatObjectString('修改数据到数据库失败：', error));
                throw error;
            }
        },

        async editFaceJsonData(json_data, id) {
            const faceIndex = this.faceList.findIndex(item => item.id == id);
            if (faceIndex === -1) {
                const message = `未找到id: ${id} 的面容信息`;
                warn(message);
                throw message;
            }
            try {
                await update('faces', { json_data }, 'id = ?', [id]);
                this.faceList[faceIndex].json_data = JSON.parse(json_data);
            } catch (error) {
                errorLog(formatObjectString('修改面容JSON数据失败：', error));
                throw error;
            }
        },

        getFaceById(id) {
            const item = this.faceList.find(item => item.id == id);
            return item ? { ...item } : null;
        },

        getFaceAliasById(id) {
            return this.getFaceById(id)?.json_data.alias ?? '未知';
        },

        addFaceToList(data) {
            this.faceList.push({
                id: data.id,
                user_name: data.user_name,
                account_type: data.account_type,
                face_token: data.face_token,
                json_data: JSON.parse(data.json_data),
                createTime: data.createTime
            });
        },

        async deleteFace(id) {
            const faceIndex = this.faceList.findIndex(item => item.id == id);
            if (faceIndex === -1) {
                const message = `未找到id: ${id} 的面容信息`;
                warn(message);
                throw message;
            }
            try {
                await deleteData('faces', 'id = ?', [id]);
                removeFace(this.faceList[faceIndex].face_token);
                this.faceList.splice(faceIndex, 1);
            } catch (error) {
                errorLog(formatObjectString('从数据库删除面容失败：', error));
                throw error;
            }
        }
    },
    state() {
        return { faceList: [] };
    }
});
