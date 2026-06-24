---
date: 2026-04-28 10:31:59
layout: post
title: 浅析 glibc 2.43 中 allocator 的一些变化
subtitle: from a "how2heap" perspective
description: >- 
    
image: >-
  /assets/img/uploads/jinan.jpg
optimized_image: >-
  /assets/img/uploads/jinan.jpg
category: ctf
tags:
  - ubuntu 26.04
  - glibc 2.43
  - heap challenges
author: rosayxy
paginate: true
---

已经有其他人写了这个 allocator 变化了，见[这篇博客](https://bbs.kanxue.com/thread-291123.htm)

主要有以下几点变化：
- calloc 会使用 tcache（爷青结）
- smallbin 大小的堆块（0x80 - 0x3ff）会直接进入 small bin 而非 unsorted bin
- tcache_perthread_struct 中由记录 counts 数组（每个 bin 中已经放了多少块）变成了记录 num_slots 数组（每个 bin 中还有多少个空位可以放堆块）
- tcache_perthread_struct 之前是在堆的基地址（对应程序首次 malloc 的时候初始化），但是现在是在首次 free 的时候初始化，所以劫持 tcache_perthread_struct 之前需要先用 tcache poisoning 这种方法，先把一个堆块扔到 tcache_perthread_struct 的位置再来劫持这个结构体，或者用 UDP 的 house of water 伪造一个 unsorted bin 堆块来劫持 tcache_perthread_struct，现在就可以直接用堆溢出开整了
- largebin attack 没了（悲），整个 fast bin 也没了（大悲，但是好像高版本中印象用 fast bin 的攻击方法也不多了）
- tcache 也分了 tcache smallbins 和 tcache largebins，具体代码如下，其中这个 TCACHE_SMALL_BINS 是 64，tcache largebins 则有 12 个，范围是 Up to 4M chunks，可见 tcache 真的在代码中广泛使用了

    ```c
    if (__glibc_likely (tc_idx < TCACHE_SMALL_BINS))
      {
        if (tcache->entries[tc_idx] != NULL)
          return tag_new_usable (tcache_get (tc_idx));
      } else {
        tc_idx = large_csize2tidx (nb);
        void *victim = tcache_get_large (tc_idx, nb);
        if (victim != NULL)
          return tag_new_usable (victim);
      }
    ```
- tcache largebins 实现大概是这样的：首先我们知道 tcache 是单向链表，而 largebin 则是双向链表，而且不仅是双向链表，还有 `fd_nextsize` 和 `bk_nextsize` 组成的双向链表，那么 tcache largebin 的实现是怎么样的呢？和 tcache 一样，它也是只有一个 next 指针，而不会有 nextsize 指针，但是插入 tcache 的时候是有对 size 的考虑的，具体来说，先会用 `entry = tcache_location_large (chunksize (chunk), tc_idx, &mangled, &te);` 函数来获取比新 free 块更大/相等的第一个 chunk，然后将被 free 的 chunk 插入到 tcache largebin 中该 chunk 之前的位置，如以下代码所示

      ```c
      static __always_inline void
      tcache_put_large (mchunkptr chunk, size_t tc_idx)
      {
        tcache_entry **entry;
        bool mangled = false;
        tcache_entry *te;
        entry = tcache_location_large (chunksize (chunk), tc_idx, &mangled, &te);

        return tcache_put_n (chunk, tc_idx, entry, mangled);
      }

      static __always_inline tcache_entry **
      tcache_location_large (size_t nb, size_t tc_idx,
                bool *mangled, tcache_entry **demangled_ptr)
      {
        tcache_entry **tep = &(tcache->entries[tc_idx]);
        tcache_entry *te = *tep;
        while (te != NULL
              && __glibc_unlikely (chunksize (mem2chunk (te)) < nb))
          {
            tep = & (te->next);
            te = REVEAL_PTR (te->next);
            *mangled = true;
          }

        *demangled_ptr = te;
        return tep;
      }

      ```

- 既然一个 tcache bin 里面可以放多个 size 的堆块，那么也很合理地，tcache 每个 bins 数量变成了 16 个，代表每次为了往 unsorted bin 扔东西，往 tcache 扔的堆块数量又增加了