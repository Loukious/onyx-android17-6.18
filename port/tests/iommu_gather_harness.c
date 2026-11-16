/* SPDX-License-Identifier: GPL-2.0-only */
/* Source functions are injected by port/verify_iommu_gather.py. */
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PAGE_BYTES 4096UL
#define IPA_IOVA 0x53c48c000UL
#define REUSED_VALUE 0xabcddcbaUL
#define DMA_VALUE 0xdeadbeefUL
#define likely(value) (value)
#define unlikely(value) (value)
#define IS_ALIGNED(value, alignment) (!((value) & ((alignment) - 1)))
#define __ffs(value) __builtin_ctzl(value)
#define __IOMMU_DOMAIN_PAGING 1U
#define ANDROID_KABI_RESERVE(number)
#define IOMMU_PAGES_LIST_INIT(list) { 0 }
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)

struct iommu_pages_list { unsigned long unused; };
/* ACTUAL_GATHER_TYPE */

struct iommu_domain;
struct io_pgtable_ops;
struct iommu_domain_ops {
	size_t (*unmap_pages)(struct iommu_domain *, unsigned long, size_t,
			      size_t, struct iommu_iotlb_gather *);
	void (*iotlb_sync)(struct iommu_domain *, struct iommu_iotlb_gather *);
};
struct iommu_domain {
	unsigned int type;
	unsigned long pgsize_bitmap;
	const struct iommu_domain_ops *ops;
};
struct io_pgtable_ops {
	size_t (*unmap_pages)(struct io_pgtable_ops *, unsigned long, size_t,
			      size_t, struct iommu_iotlb_gather *);
};
struct arm_smmu_domain {
	struct iommu_domain domain;
	struct io_pgtable_ops *pgtbl_ops;
};

static struct {
	size_t available;
	size_t pending_invalidations;
	unsigned int pending_table_pages;
	unsigned int backend_calls;
	unsigned int sync_calls;
	unsigned int warnings;
	unsigned int traces;
	unsigned int step;
	unsigned int sync_step;
	unsigned int reuse_step;
	unsigned long synced_start;
	unsigned long synced_end;
	unsigned long reused_memory;
	bool stale_dma_translation;
	bool generic_backend;
	bool queued_at_sync;
} model;

static struct arm_smmu_domain *to_smmu_domain(struct iommu_domain *domain)
{
	return (struct arm_smmu_domain *)((char *)domain -
				       offsetof(struct arm_smmu_domain, domain));
}

static bool mock_warn(bool value)
{
	model.warnings += value;
	return value;
}
#define WARN_ON(value) mock_warn(value)

static void trace_unmap_pages(struct arm_smmu_domain *domain,
			     unsigned long iova, size_t pgsize, size_t count)
{
	(void)domain; (void)iova; (void)pgsize; (void)count;
	model.traces++;
}

static void trace_unmap(unsigned long iova, size_t size, size_t unmapped)
{
	(void)iova; (void)size; (void)unmapped;
}

/* Only 4K pages are advertised in this mock domain. */
static size_t iommu_pgsize(struct iommu_domain *domain, unsigned long iova,
			  unsigned long paddr, size_t size, size_t *count)
{
	(void)domain; (void)iova; (void)paddr;
	*count = size / PAGE_BYTES;
	return PAGE_BYTES;
}

/* ACTUAL_FUNCTIONS */

/*
 * Removing PTEs does not invalidate cached DMA translations. Qualcomm's
 * private pending invalidation and page-table queue require a later sync.
 */
static size_t backend_unmap(struct io_pgtable_ops *ops, unsigned long iova,
			    size_t pgsize, size_t count,
			    struct iommu_iotlb_gather *gather)
{
	size_t requested = pgsize * count;
	size_t removed = model.available < requested ? model.available : requested;

	(void)ops;
	model.backend_calls++;
	model.available -= removed;
	if (removed) {
		model.pending_invalidations += removed;
		model.pending_table_pages++;
		model.stale_dma_translation = true;
		if (model.generic_backend && gather)
			iommu_iotlb_gather_add_range(gather, iova, removed);
	}
	return removed;
}

/* Model the vendor's full-context invalidation and private freelist drain. */
static void domain_sync(struct iommu_domain *domain,
			struct iommu_iotlb_gather *gather)
{
	(void)domain;
	model.sync_calls++;
	model.sync_step = ++model.step;
	if (gather) {
		model.synced_start = gather->start;
		model.synced_end = gather->end;
		model.queued_at_sync = gather->queued;
	}
	model.pending_invalidations = 0;
	model.pending_table_pages = 0;
	model.stale_dma_translation = false;
}

static struct io_pgtable_ops backend_ops = { .unmap_pages = backend_unmap };
static const struct iommu_domain_ops domain_ops = {
	.unmap_pages = arm_smmu_unmap_pages,
	.iotlb_sync = domain_sync,
};

static struct arm_smmu_domain reset_model(size_t available, bool generic)
{
	memset(&model, 0, sizeof(model));
	model.available = available;
	model.generic_backend = generic;
	return (struct arm_smmu_domain) {
		.domain = {
			.type = __IOMMU_DOMAIN_PAGING,
			.pgsize_bitmap = PAGE_BYTES,
			.ops = &domain_ops,
		},
		.pgtbl_ops = &backend_ops,
	};
}

/* A stale device write must never reach memory assigned to its new owner. */
static bool reuse_dma_memory(void)
{
	model.reuse_step = ++model.step;
	model.reused_memory = REUSED_VALUE;
	if (model.stale_dma_translation)
		model.reused_memory = DMA_VALUE;
	return model.reused_memory == REUSED_VALUE &&
		!model.pending_invalidations && !model.pending_table_pages &&
		model.sync_step && model.sync_step < model.reuse_step;
}

#define CHECK(condition, reason) do { \
	if (!(condition)) { \
		fprintf(stderr, "%s: %s\n", __func__, reason); \
		return false; \
	} \
} while (0)

static bool qcom_success(void)
{
	struct arm_smmu_domain domain = reset_model(4 * PAGE_BYTES, false);

	CHECK(iommu_unmap(&domain.domain, IPA_IOVA, 4 * PAGE_BYTES) == 4 * PAGE_BYTES,
	      "wrong unmapped size");
	CHECK(reuse_dma_memory(), "DMA memory reuse occurred without completed TLB sync");
	CHECK(model.sync_calls == 1, "expected one domain sync");
	CHECK(model.synced_start == IPA_IOVA &&
	      model.synced_end == IPA_IOVA + 4 * PAGE_BYTES - 1,
	      "sync did not cover the actual unmapped range");
	return true;
}

static bool qcom_partial(void)
{
	struct arm_smmu_domain domain = reset_model(2 * PAGE_BYTES, false);

	CHECK(iommu_unmap(&domain.domain, IPA_IOVA, 4 * PAGE_BYTES) == 2 * PAGE_BYTES,
	      "partial backend result was lost");
	CHECK(model.backend_calls == 2, "core did not stop at the first unmapped hole");
	CHECK(reuse_dma_memory(), "DMA memory reuse occurred without completed TLB sync");
	CHECK(model.sync_calls == 1 && model.synced_start == IPA_IOVA &&
	      model.synced_end == IPA_IOVA + 2 * PAGE_BYTES - 1,
	      "collector included bytes the backend did not unmap");
	return true;
}

static bool no_unmap(void)
{
	struct arm_smmu_domain domain = reset_model(0, false);

	CHECK(iommu_unmap(&domain.domain, IPA_IOVA, PAGE_BYTES) == 0,
	      "empty mapping returned bytes");
	CHECK(!model.sync_calls && !model.pending_invalidations && !model.traces,
	      "no-op unmap changed pending work or triggered sync");
	return true;
}

static bool null_gather(void)
{
	struct arm_smmu_domain domain = reset_model(PAGE_BYTES, false);

	CHECK(arm_smmu_unmap_pages(&domain.domain, IPA_IOVA, PAGE_BYTES, 1, NULL)
	      == PAGE_BYTES, "NULL-gather private call failed");
	CHECK(!model.sync_calls && model.pending_invalidations == PAGE_BYTES,
	      "private caller lost responsibility for explicit synchronization");
	domain_sync(&domain.domain, NULL);
	CHECK(reuse_dma_memory(), "manual private flush did not make reuse safe");
	return true;
}

static bool missing_backend(void)
{
	struct arm_smmu_domain domain = reset_model(PAGE_BYTES, false);

	domain.pgtbl_ops = NULL;
	CHECK(iommu_unmap(&domain.domain, IPA_IOVA, PAGE_BYTES) == 0,
	      "missing backend returned bytes");
	CHECK(!model.backend_calls && !model.sync_calls,
	      "missing backend attempted work");
	return true;
}

static bool generic_prepopulated(void)
{
	struct arm_smmu_domain domain = reset_model(2 * PAGE_BYTES, true);

	CHECK(iommu_unmap(&domain.domain, IPA_IOVA, 2 * PAGE_BYTES) == 2 * PAGE_BYTES,
	      "generic backend failed");
	CHECK(reuse_dma_memory(), "generic backend did not synchronize");
	CHECK(model.sync_calls == 1 && model.synced_start == IPA_IOVA &&
	      model.synced_end == IPA_IOVA + 2 * PAGE_BYTES - 1,
	      "publishing the same generic range changed its extent or sync count");
	return true;
}

static bool generic_broad_range(void)
{
	struct arm_smmu_domain domain = reset_model(PAGE_BYTES, true);
	struct iommu_iotlb_gather gather;

	iommu_iotlb_gather_init(&gather);
	iommu_iotlb_gather_add_range(&gather, IPA_IOVA - PAGE_BYTES, 4 * PAGE_BYTES);
	CHECK(arm_smmu_unmap_pages(&domain.domain, IPA_IOVA, PAGE_BYTES, 1, &gather)
	      == PAGE_BYTES, "generic narrow unmap failed");
	CHECK(gather.start == IPA_IOVA - PAGE_BYTES &&
	      gather.end == IPA_IOVA + 3 * PAGE_BYTES - 1,
	      "preexisting broader range was overwritten");
	iommu_iotlb_sync(&domain.domain, &gather);
	CHECK(reuse_dma_memory(), "generic batched range did not synchronize");
	return true;
}

static bool qcom_batch(void)
{
	struct arm_smmu_domain domain = reset_model(2 * PAGE_BYTES, false);
	struct iommu_iotlb_gather gather;

	iommu_iotlb_gather_init(&gather);
	CHECK(arm_smmu_unmap_pages(&domain.domain, IPA_IOVA, PAGE_BYTES, 1, &gather)
	      == PAGE_BYTES, "first batch unmap failed");
	CHECK(arm_smmu_unmap_pages(&domain.domain, IPA_IOVA + 3 * PAGE_BYTES,
				  PAGE_BYTES, 1, &gather) == PAGE_BYTES,
	      "second batch unmap failed");
	CHECK(!model.sync_calls && model.pending_invalidations == 2 * PAGE_BYTES,
	      "range accumulation triggered an intermediate flush");
	iommu_iotlb_sync(&domain.domain, &gather);
	CHECK(reuse_dma_memory(), "DMA memory reuse occurred without completed TLB sync");
	CHECK(model.sync_calls == 1 && model.synced_start == IPA_IOVA &&
	      model.synced_end == IPA_IOVA + 4 * PAGE_BYTES - 1,
	      "batched collector did not retain both ranges");
	CHECK(gather.start == ULONG_MAX && !gather.end,
	      "common sync did not reset the collector");
	return true;
}

static bool qcom_queued(void)
{
	struct arm_smmu_domain domain = reset_model(PAGE_BYTES, false);
	struct iommu_iotlb_gather gather;

	iommu_iotlb_gather_init(&gather);
	gather.queued = true;
	CHECK(arm_smmu_unmap_pages(&domain.domain, IPA_IOVA, PAGE_BYTES, 1, &gather)
	      == PAGE_BYTES, "queued unmap failed");
	CHECK(gather.queued && !model.sync_calls, "wrapper changed queued semantics");
	iommu_iotlb_sync(&domain.domain, &gather);
	CHECK(reuse_dma_memory(), "DMA memory reuse occurred without completed TLB sync");
	CHECK(model.queued_at_sync, "callback did not receive the queued flag");
	return true;
}

static bool zero_preserves_pending_range(void)
{
	struct arm_smmu_domain domain = reset_model(0, false);
	struct iommu_iotlb_gather gather;

	iommu_iotlb_gather_init(&gather);
	iommu_iotlb_gather_add_range(&gather, IPA_IOVA, PAGE_BYTES);
	model.pending_invalidations = PAGE_BYTES;
	model.pending_table_pages = 1;
	model.stale_dma_translation = true;
	CHECK(arm_smmu_unmap_pages(&domain.domain, IPA_IOVA + 2 * PAGE_BYTES,
				  PAGE_BYTES, 1, &gather) == 0,
	      "no-op returned bytes");
	CHECK(gather.start == IPA_IOVA && gather.end == IPA_IOVA + PAGE_BYTES - 1,
	      "no-op unmap damaged the previous pending range");
	iommu_iotlb_sync(&domain.domain, &gather);
	CHECK(reuse_dma_memory(), "previous pending mapping was not synchronized");
	return true;
}

static bool qcom_top_iova(void)
{
	struct arm_smmu_domain domain = reset_model(PAGE_BYTES, false);
	unsigned long iova = ULONG_MAX - PAGE_BYTES + 1;

	CHECK(iommu_unmap(&domain.domain, iova, PAGE_BYTES) == PAGE_BYTES,
	      "top-of-address-space unmap failed");
	CHECK(reuse_dma_memory(), "DMA memory reuse occurred without completed TLB sync");
	CHECK(model.synced_start == iova && model.synced_end == ULONG_MAX,
	      "inclusive end at ULONG_MAX was lost");
	return true;
}

int main(void)
{
	const struct {
		const char *name;
		bool (*run)(void);
	} cases[] = {
		{ "qcom_success", qcom_success },
		{ "qcom_partial", qcom_partial },
		{ "no_unmap", no_unmap },
		{ "null_gather", null_gather },
		{ "missing_backend", missing_backend },
		{ "generic_prepopulated", generic_prepopulated },
		{ "generic_broad_range", generic_broad_range },
		{ "qcom_batch", qcom_batch },
		{ "qcom_queued", qcom_queued },
		{ "zero_preserves_pending_range", zero_preserves_pending_range },
		{ "qcom_top_iova", qcom_top_iova },
	};
	unsigned int failed = 0;

	printf("{\"cases\":[");
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		bool passed = cases[i].run();

		if (model.warnings) {
			fprintf(stderr, "%s: unexpected core WARN_ON\n", cases[i].name);
			passed = false;
		}
		failed += !passed;
		printf("%s{\"name\":\"%s\",\"passed\":%s}",
		       i ? "," : "", cases[i].name, passed ? "true" : "false");
	}
	printf("],\"failed\":%u}\n", failed);
	return failed ? 1 : 0;
}
