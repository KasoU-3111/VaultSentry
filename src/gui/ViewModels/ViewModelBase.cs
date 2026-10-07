using CommunityToolkit.Mvvm.ComponentModel;

namespace VaultSentry.Client.ViewModels;

/// <summary>
/// Abstract base class for all ViewModels in the VaultSentry application.
/// Provides reactive property notification support via <see cref="ObservableObject"/>.
/// </summary>
public abstract class ViewModelBase : ObservableObject
{
}