<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import AppLayout from '@/components/AppLayout.vue'
import ToastContainer from '@/components/ui/ToastContainer.vue'

const route = useRoute()
const isAuthPage = computed(() => route.path === '/login')
</script>

<template>
  <ToastContainer />
  <router-view v-if="isAuthPage" />
  <AppLayout v-else>
    <router-view />
  </AppLayout>
</template>
