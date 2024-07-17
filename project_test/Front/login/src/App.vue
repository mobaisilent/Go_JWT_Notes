<script setup>
import { reactive, toRefs, ref } from 'vue';

const state = reactive({
  form: {
    username: '',
    password: ''
  },
  isLoggedIn: false
});
// 创建响应式数据

function submitForm() {
  fetch('http://localhost:12345/auth', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(state.form)
    // 将响应式表单数据转为JSON字符串的形式
  })
    .then(response => {
      if (!response.ok) {
        console.log("请求失败");
      }
      else {
        return response.json();
      }
    })
    .then(data => {
      console.log(data);
      // 打印响应数据
      if (data.data.token) {
        state.isLoggedIn = true;
        window.localStorage.setItem('token', data.data.token);
        // 创建token浏览器变量
      }
    })
};
// 创建异步请求 提交表单数据  :使用fetch比较方便

// 将响应式对象转换为引用，以便在模板中使用
const { form } = toRefs(state);

const click = ref(true)
const trueusername = ref()

function hideButton() {
  fetch("http://localhost:12345/home", {
    method: "GET",
    headers: {
      "authorization": `Bearer ${window.localStorage.getItem('token')}`
    }
  })
    .then(response => {
      // console.log(window.localStorage.getItem('token')) // 测试
      if (!response.ok) {
        console.log("请求失败");
      } else {
        return response.json();
      }
    })
    .then(data => {
      console.log(data);
      trueusername.value = data.data.username;
      click.value = false;
    })
    .catch(error => {
      console.error(error);
    });
}
</script>

<template>
  <div class="form-container">
    <form @submit.prevent="submitForm">
      <label for="username">用户名:</label>
      <input id="username" v-model="form.username" type="text" required>

      <label for="password">密码:</label>
      <input id="password" v-model="form.password" type="password" required>

      <button type="submit">提交</button>
    </form>
  </div>
  <div class="check" v-if="state.isLoggedIn">
    <p v-if="click">恭喜你登录成功</p>
    <!-- 提交的时候就调用submitForm方法 -->
    <button v-if="click" class="checkbutton" id="checkbutton" @click="hideButton">查看信息</button>
    <p v-if="!click">username:{{ trueusername }}</p>
  </div>
</template>

<style scoped>
.form-container {
  position: absolute;
  display: flex;
  justify-content: center;
  align-items: center;
  width: 200px;
  height: 150px;
  border: 2px solid black;
  top: 30%;
  left: 50%;
  transform: translate(-50%, -50%);
  border-radius: 10px;

}

form {
  display: flex;
  flex-direction: column;
}

.check {
  display: flex;
  flex-direction: column;
  position: absolute;
  align-items: center;
  justify-content: center;
  width: 200px;
  height: 150px;
  border: 2px solid black;
  top: 60%;
  left: 50%;
  transform: translate(-50%, -50%);
  border-radius: 10px;
}
</style>
