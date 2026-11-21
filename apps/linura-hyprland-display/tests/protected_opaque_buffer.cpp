// Real GLES framebuffer readback, on the pinned builder's software renderer.
// This does not attest physical scanout, compositor coverage or native input.
#include "protected_opaque_buffer.h"

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

using namespace Linura::HyprlandDisplay;

int main()
{
    const auto display =
        eglGetPlatformDisplay(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, nullptr);
    EGLint major = 0, minor = 0;
    assert(display != EGL_NO_DISPLAY && eglInitialize(display, &major, &minor));
    assert(eglBindAPI(EGL_OPENGL_ES_API));
    constexpr EGLint attributes[] = {EGL_SURFACE_TYPE,
                                     EGL_PBUFFER_BIT,
                                     EGL_RENDERABLE_TYPE,
                                     EGL_OPENGL_ES3_BIT,
                                     EGL_RED_SIZE,
                                     8,
                                     EGL_GREEN_SIZE,
                                     8,
                                     EGL_BLUE_SIZE,
                                     8,
                                     EGL_ALPHA_SIZE,
                                     8,
                                     EGL_NONE};
    EGLConfig config{};
    EGLint count = 0;
    assert(eglChooseConfig(display, attributes, &config, 1, &count) && count == 1);
    constexpr EGLint contextAttributes[] = {EGL_CONTEXT_MAJOR_VERSION, 3, EGL_CONTEXT_MINOR_VERSION,
                                            2, EGL_NONE};
    constexpr EGLint surfaceAttributes[] = {EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE};
    const auto context = eglCreateContext(display, config, EGL_NO_CONTEXT, contextAttributes);
    const auto surface = eglCreatePbufferSurface(display, config, surfaceAttributes);
    assert(context != EGL_NO_CONTEXT && surface != EGL_NO_SURFACE);
    assert(eglMakeCurrent(display, surface, surface, context));

    GLuint framebuffer = 0, texture = 0;
    glGenFramebuffers(1, &framebuffer);
    glGenTextures(1, &texture);
    glBindFramebuffer(GL_FRAMEBUFFER, framebuffer);
    glBindTexture(GL_TEXTURE_2D, texture);
    for (const auto size : {std::array<int, 2>{17, 13}, {257, 129}, {13, 17}, {129, 257}}) {
        const auto bytes = static_cast<std::size_t>(size[0] * size[1] * 4);
        const auto seed = std::vector<std::uint8_t>(bytes, 127);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, size[0], size[1], 0, GL_RGBA, GL_UNSIGNED_BYTE,
                     seed.data());
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, texture, 0);
        // Old-size viewport/damage/transform and inherited masks are hostile
        // initial state. Every pixel of the new, rotated/larger buffer must be
        // initialized, including storage outside the former visible region.
        glViewport(0, 0, 1, 1);
        glScissor(3, 2, 4, 5);
        glEnable(GL_SCISSOR_TEST);
        glColorMask(GL_FALSE, GL_TRUE, GL_FALSE, GL_FALSE);
        assert(clearProtectedFramebuffer());
        GLboolean mask[4]{};
        glGetBooleanv(GL_COLOR_WRITEMASK, mask);
        assert(mask[0] == GL_FALSE && mask[1] == GL_TRUE && mask[2] == GL_FALSE &&
               mask[3] == GL_FALSE && glIsEnabled(GL_SCISSOR_TEST));
        GLint scissor[4]{};
        glGetIntegerv(GL_SCISSOR_BOX, scissor);
        assert(scissor[0] == 3 && scissor[1] == 2 && scissor[2] == 4 && scissor[3] == 5);
        std::vector<std::uint8_t> pixels(bytes);
        glReadPixels(0, 0, size[0], size[1], GL_RGBA, GL_UNSIGNED_BYTE, pixels.data());
        assert(glGetError() == GL_NO_ERROR);
        for (std::size_t i = 0; i < bytes; i += 4)
            assert(pixels[i] == 0 && pixels[i + 1] == 0 && pixels[i + 2] == 0 &&
                   pixels[i + 3] == 255);
    }
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, 0, 0);
    assert(!clearProtectedFramebuffer()); // Incomplete storage never qualifies.
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glDeleteTextures(1, &texture);
    glDeleteFramebuffers(1, &framebuffer);
    assert(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT));
    assert(eglDestroySurface(display, surface) && eglDestroyContext(display, context));
    assert(eglTerminate(display));
}
