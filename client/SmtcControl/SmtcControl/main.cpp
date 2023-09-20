#include <iostream>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Media.Control.h>
#include <winrt/Windows.Foundation.Collections.h>

#include <windows.h>
#include <mmdeviceapi.h>
#include <endpointvolume.h>

namespace media_control = winrt::Windows::Media::Control;
using SessionStatus = media_control::GlobalSystemMediaTransportControlsSessionPlaybackStatus;

bool PausePlay(const auto& status, const auto& supported_commands, auto& session) {
    if (supported_commands.IsPlayPauseToggleEnabled()) {
        return session.TryTogglePlayPauseAsync().get();
    }
    if (status == SessionStatus::Playing && supported_commands.IsPauseEnabled()) {
        return session.TryPauseAsync().get();
    }
    if (status == SessionStatus::Paused && supported_commands.IsPlayEnabled()) {
        return session.TryPlayAsync().get();
    }
    return false;
}

bool NextTrack(const auto& supported_commands, auto& session) {
    if (supported_commands.IsNextEnabled()) {
        return session.TrySkipNextAsync().get();
    }
    return false;
}

bool PrevTrack(const auto& supported_commands, auto& session) {
    if (supported_commands.IsPreviousEnabled()) {
        return session.TrySkipPreviousAsync().get();
    }
    return false;
}

int MediaControl(const std::string& action) {
    auto session_manager = media_control::GlobalSystemMediaTransportControlsSessionManager:: RequestAsync().get();
    auto current_session = session_manager.GetCurrentSession();

    if (!current_session) {
        return 4;
    }
    auto playback_info = current_session.GetPlaybackInfo();
    auto status = playback_info.PlaybackStatus();
    auto supported_commands = playback_info.Controls();

    if (action == "pause") {
        return PausePlay(status, supported_commands, current_session) ? 0 : 2;
    } else if (action == "next") {
        return NextTrack(supported_commands, current_session) ? 0 : 2;
    } else if (action == "prev") {
        return PrevTrack(supported_commands, current_session) ? 0 : 2;
    } else {
        return 3;
    }
}

float RoundVolume(float value) {
    return roundf(value * 50.0f) / 50.0f;
}

int VolumnControl(const std::string& action) {
    CoInitialize(nullptr);

    IMMDeviceEnumerator* deviceEnumerator = nullptr;
    HRESULT hr = CoCreateInstance(
        __uuidof(MMDeviceEnumerator), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(IMMDeviceEnumerator), (LPVOID*)&deviceEnumerator);

    IMMDevice* defaultDevice = nullptr;
    hr = deviceEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &defaultDevice);
    deviceEnumerator->Release();

    IAudioEndpointVolume* endpointVolume = nullptr;
    hr = defaultDevice->Activate(__uuidof(IAudioEndpointVolume),
                                 CLSCTX_INPROC_SERVER, nullptr,
                                 (LPVOID*)&endpointVolume);
    defaultDevice->Release();

    float currentVolume = 0;
    endpointVolume->GetMasterVolumeLevelScalar(&currentVolume);

    if (action == "vol_up") {
        currentVolume += 0.02f;
        currentVolume = RoundVolume(currentVolume);
    } else if (action == "vol_down") {
        currentVolume -= 0.02f;
        currentVolume = RoundVolume(currentVolume);
    } else if (action == "vol_mute") {
        BOOL isMuted;
        endpointVolume->GetMute(&isMuted);
        if (isMuted) {
          endpointVolume->SetMute(FALSE, nullptr);
        } else {
          endpointVolume->SetMute(TRUE, nullptr);
        }
        endpointVolume->Release();
        CoUninitialize();
        return 0;  // OK
    } else {
        endpointVolume->Release();
		CoUninitialize();
		return 3;  // Unknown action
    }

    hr = endpointVolume->SetMasterVolumeLevelScalar(currentVolume, nullptr);
    endpointVolume->Release();
    CoUninitialize();

    return (hr == S_OK) ? 0 : 2;
}

int Control(const std::string& action) {
    if (action == "pause" || action == "next" || action == "prev") {
        return MediaControl(action);
    } else if (action == "vol_up" || action == "vol_down" || action == "vol_mute") {
		return VolumnControl(action);
	} else {
		return 3;
    }
}

// 0: OK, 1: Unhandled Exceptions, 2. Unable to take action, 3: Unknown action, 4: Can't get current session
// Action: pause (toggle), next, prev, vol_up, vol_down, vol_mute
int main(int argc, char* argv[]) {
    winrt::init_apartment();

    if (argc == 1) {
        return 3;
    }
    try {
        return Control(argv[1]);
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}
