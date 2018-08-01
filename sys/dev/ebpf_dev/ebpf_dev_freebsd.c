/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2017-2018 Yutaro Hayakawa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dev/ebpf/ebpf_platform.h>
#include <dev/ebpf_dev/ebpf_dev_platform.h>
#include <sys/ebpf.h>
#include <sys/ebpf_obj.h>
#include <sys/ebpf_dev.h>

int
ebpf_fopen(ebpf_thread_t *td, ebpf_file_t **fp, int *fd, struct ebpf_obj *eo)
{
	int error;

	if (!td || !fp || !fd || !eo) {
		return EINVAL;
	}

	error = falloc(td, fp, fd, 0);
	if (error) {
		return error;
	}
	/*
	 * finit reserves two reference count for us, so release one
	 * since we don't need it.
	 */
	finit(*fp, FREAD | FWRITE, DTYPE_NONE, eo, &ebpf_obj_fileops);
	fdrop(*fp, td);

	EBPF_DPRINTF("%s: leave fp=%p fp->f_data=%p\n", __func__, (*fp),
	    (*fp)->f_data);

	return 0;
}

int
ebpf_fget(ebpf_thread_t *td, int fd, ebpf_file_t **f)
{
#if __FreeBSD_version >= 1200062
	return fget(td, fd, &cap_ioctl_rights, f);
#else
	cap_rights_t cap;
	return fget(td, fd, cap_rights_init(&cap, CAP_IOCTL), f);
#endif
}

int
ebpf_fdrop(ebpf_file_t *f, ebpf_thread_t *td)
{
	return fdrop(f, td);
}

int
ebpf_copyin(const void *uaddr, void *kaddr, size_t len)
{
	return copyin(uaddr, kaddr, len);
}

int
ebpf_copyout(const void *kaddr, void *uaddr, size_t len)
{
	return copyout(kaddr, uaddr, len);
}

ebpf_thread_t *
ebpf_curthread(void)
{
	return curthread;
}

/*
 * Character device operations
 */
static int
ebpf_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	return 0;
}

static int
ebpf_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	return 0;
}

static int
freebsd_ebpf_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int ffla,
		   struct thread *td)
{
	int error;
	error = ebpf_ioctl(cmd, data, td);
	return error;
}

static struct cdev *ebpf_dev;
static struct cdevsw ebpf_cdevsw = {.d_version = D_VERSION,
				    .d_name = "ebpf",
				    .d_open = ebpf_open,
				    .d_ioctl = freebsd_ebpf_ioctl,
				    .d_close = ebpf_close};

/*
 * Kernel module operations
 */
void ebpf_dev_fini(void);
int ebpf_dev_init(void);

void
ebpf_dev_fini(void)
{
	if (ebpf_dev) {
		destroy_dev(ebpf_dev);
	}
	printf("ebpf-dev unloaded\n");
}

int
ebpf_dev_init(void)
{
	ebpf_dev = make_dev_credf(MAKEDEV_ETERNAL_KLD, &ebpf_cdevsw, 0, NULL,
				  UID_ROOT, GID_WHEEL, 0600, "ebpf");
	if (!ebpf_dev) {
		goto fail;
	}

	printf("ebpf-dev loaded\n");
	return 0;
fail:
	ebpf_dev_fini();
	return EINVAL;
}

static int
ebpf_dev_loader(__unused struct module *module, int event, __unused void *arg)
{
	int error = 0;

	switch (event) {
	case MOD_LOAD:
		error = ebpf_dev_init();
		break;
	case MOD_UNLOAD:
		ebpf_dev_fini();
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

DEV_MODULE(ebpf_dev, ebpf_dev_loader, NULL);
MODULE_DEPEND(ebpf_dev, ebpf, 1, 1, 1);
MODULE_VERSION(ebpf_dev, 1);
