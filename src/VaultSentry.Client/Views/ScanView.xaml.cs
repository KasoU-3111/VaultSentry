using System.Windows.Controls;

namespace VaultSentry.Client.Views
{
    /// <summary>
    /// Interaction logic for ScanView.xaml.
    /// DataContext is inherited automatically via MainViewModel DataTemplate binding.
    /// Fixes CS7036 compilation error.
    /// </summary>
    public partial class ScanView : UserControl
    {
        public ScanView()
        {
            InitializeComponent();
        }
    }
}