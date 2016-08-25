#include "client/linux/handler/exception_handler.h"
#include "common/linux/linux_libc_support.h"
#include "third_party/lss/linux_syscall_support.h"

// Processor headers for dedup.
#include "google_breakpad/processor/minidump.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "google_breakpad/processor/call_stack.h"
#include "google_breakpad/processor/stack_frame.h"
#include "processor/pathname_stripper.h"

#include "sha1.h"

#include <signal.h>
#include <dirent.h>
#include <unistd.h>
#include <setjmp.h>

using google_breakpad::Minidump;
using google_breakpad::MinidumpProcessor;
using google_breakpad::ProcessState;
using google_breakpad::ProcessResult;
using google_breakpad::CallStack;
using google_breakpad::StackFrame;
using google_breakpad::PathnameStripper;

jmp_buf postDumpReturn;
char minidumpPath[512];

static bool dumpCallback(const google_breakpad::MinidumpDescriptor &descriptor, void *context, bool succeeded)
{
	if (succeeded) {
		sys_write(STDERR_FILENO, "Wrote minidump to: ", 19);
	} else {
		sys_write(STDERR_FILENO, "Failed to write minidump to: ", 29);
	}

	sys_write(STDERR_FILENO, descriptor.path(), my_strlen(descriptor.path()));
	sys_write(STDERR_FILENO, "\n", 1);

	my_strlcpy(minidumpPath, descriptor.path(), sizeof(minidumpPath));

	siglongjmp(postDumpReturn, succeeded ? 2 : 1);

	return succeeded;
}

int process(const char *path, bool delete_after)
{
	google_breakpad::SymbolSupplier *symbolSupplier = NULL;
	google_breakpad::SourceLineResolverInterface *sourceLineResolverInterface = NULL;
	MinidumpProcessor minidumpProcessor(symbolSupplier, sourceLineResolverInterface, false);

	ProcessState processState;
	ProcessResult processResult = minidumpProcessor.Process(path, &processState);

	if (processResult == google_breakpad::PROCESS_ERROR_MINIDUMP_NOT_FOUND) {
		fprintf(stderr, "Minidump doesn't exist.\n");
		return 1;
	}

	if (processResult != google_breakpad::PROCESS_OK) {
		fprintf(stderr, "Failed to process minidump.\n");
		return 1;
	}

	fprintf(stderr, "Sucessfully processed minidump.\n");

	if (delete_after) {
		unlink(path);
	}

	// If there is no requesting thread, print the main thread.
	int requestingThread = processState.requesting_thread();
	if (requestingThread == -1) {
		requestingThread = 0;
	}

	const CallStack *stack = processState.threads()->at(requestingThread);
	if (!stack) {
		fprintf(stderr, "Missing stack for thread %d.\n", requestingThread);
		return 1;
	}

	int frameCount = stack->frames()->size();
	if (frameCount > 10) {
		frameCount = 10;
	}

	SHA1_CTX shaContext;
	SHA1Init(&shaContext);

	for (int frameIndex = 0; frameIndex < frameCount; ++frameIndex) {
		const StackFrame *frame = stack->frames()->at(frameIndex);

		if (!frame->module) {
			continue;
		}

		const std::string debug_file = PathnameStripper::File(frame->module->debug_file());
		SHA1Update(&shaContext, (const unsigned char *)debug_file.c_str(), debug_file.length());

		const std::string debug_identifier = frame->module->debug_identifier();
		SHA1Update(&shaContext, (const unsigned char *)debug_identifier.c_str(), debug_identifier.length());

		uint64_t address = frame->ReturnAddress() - frame->module->base_address();
		SHA1Update(&shaContext, (const unsigned char *)&address, sizeof(address));

/*
		unsigned char debugFileDigest[20];
		SHA1_CTX shaContext;
		SHA1Init(&shaContext);
		SHA1Update(&shaContext, (const unsigned char *)debug_file.c_str(), debug_file.length());
		SHA1Final(debugFileDigest, &shaContext);

		for (unsigned i = 0; i < sizeof(debugFileDigest); ++i)
			printf("%02X", debugFileDigest[i]);
		printf("%s%llX", frame->module->debug_identifier().c_str(), frame->ReturnAddress() - frame->module->base_address());
*/
	}

	unsigned char stackDigest[20];
	SHA1Final(stackDigest, &shaContext);

	for (unsigned i = 0; i < sizeof(stackDigest); ++i)
		printf("%02X", stackDigest[i]);

	printf("\n");

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc > 1) {
		for (int i = 1; i < argc; ++i) {
			printf("%s: ", argv[i]);
			if (process(argv[i], false) != 0)
				printf("ERROR\n");
		}

		return 0;
	}

	google_breakpad::MinidumpDescriptor descriptor(".");
	google_breakpad::ExceptionHandler *handler = new google_breakpad::ExceptionHandler(descriptor, NULL, dumpCallback, NULL, true, -1);

	fprintf(stderr, "Crash handler installed, crashing...\n");

	int retval = sigsetjmp(postDumpReturn, 1);
	if (retval == 0) {
		// Test shit here.
		__builtin_trap();
	}
	retval -= 1;

	fprintf(stderr, "Returned from crash handler: %d, \"%s\"\n", retval, minidumpPath);

	return process(minidumpPath, true);
}
